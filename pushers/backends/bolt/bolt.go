package bolt

import (
	"errors"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/boltdb/bolt"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/pushers/event"
)

var (
	_ = pushers.RegisterBackend("boltdb", NewWith)
)

// SaveRequest defines a struct object which is used to issue a SAVE
// operation to the BoltServer
type SaveRequest struct {
	Bucket   []byte
	Events   []event.Event
	Response chan error
}

// BucketSizeResquest defines a struct object which is used to issue a GET
// operation to the BoltServer for retrieving bucket records size value.
type BucketSizeResquest struct {
	Bucket   []byte
	Response chan BucketSizeResponse
}

// BucketSizeResponse defines the object used as response for a BucketSizeRequest to
// a consula.
type BucketSizeResponse struct {
	Size  int
	Error error
}

// NewBucketRequest defines a struct object which is used to issue a new bucket
// operation to the BoltServer for retrieving bucket data.
type NewBucketRequest struct {
	Bucket   []byte
	Response chan error
}

// GetRequest defines a struct object which is used to issue a GET
// operation to the BoltServer for retrieving bucket data.
type GetRequest struct {
	Bucket   []byte
	From     int
	Total    int
	Response chan GetResponse
}

// GetResponse defines a struct which is delivered as response to a giving
// GetRequest for a specific bucket.
type GetResponse struct {
	Error  error
	Events []event.Event
}

// Option defines a type which is used to upgrade a Consula instance.
type Option func(*Consula)

// Apply applies the provided options has to the provided
// Consula instance.
func Apply(ops ...Option) Option {
	return func(cs *Consula) {
		for _, option := range ops {
			option(cs)
		}
	}
}

// BucketSizeRequests sets the chan for the Consula to use for get requests.
func BucketSizeRequests(in chan BucketSizeResquest) Option {
	return func(cs *Consula) {
		cs.br = in
	}
}

// NewBucketRequests sets the chan for the Consula to use for get requests.
func NewBucketRequests(in chan NewBucketRequest) Option {
	return func(cs *Consula) {
		cs.nbr = in
	}
}

// GetRequests sets the chan for the Consula to use for get requests.
func GetRequests(in chan GetRequest) Option {
	return func(cs *Consula) {
		cs.gr = in
	}
}

// SaveRequests sets the chan for the Consula to use for get requests.
func SaveRequests(in chan SaveRequest) Option {
	return func(cs *Consula) {
		cs.svr = in
	}
}

// Consula defines a service handler which provides a central channel
// which manages all operations on a boltdb instance.
type Consula struct {
	db *bolt.DB

	wg sync.WaitGroup

	closer chan struct{}

	// Channels for size request and response.
	br chan BucketSizeResquest

	// Channels for new bucket request and response.
	nbr chan NewBucketRequest

	// Channels for GET request and response.
	gr chan GetRequest

	// Channels for SAVE request and response.
	svr chan SaveRequest
}

// New returns a new instance of a Consula for boltdb requests.
func New(dbName string, options ...Option) (*Consula, error) {
	db, err := NewBoltDB(dbName, "events")
	if err != nil {
		return nil, err
	}

	con := &Consula{
		db:     db,
		closer: make(chan struct{}),
	}

	for _, option := range options {
		option(con)
	}

	go con.manage()
	return con, nil
}

// Config defines a type to contain the configuration values for
// a giving Consula instance.
type Config struct {
	Name string `toml:"name"`
}

// NewWith defines a function to return a pushers.Backend which delivers
// new messages to a giving underline slack channel defined by the configuration
// retrieved from the giving toml.Primitive.
func NewWith(meta toml.MetaData, data toml.Primitive) (pushers.Channel, error) {
	var config Config

	if err := meta.PrimitiveDecode(data, &config); err != nil {
		return nil, err
	}

	if config.Name == "" {
		return nil, errors.New("Invalid Config: Name can not be empty")
	}

	// Create Consula instance with a default save channel.
	return New(config.Name, SaveRequests(make(chan SaveRequest)))
}

// manage defines the core of the Consula which manages request and operations in
// relation to the bolt.DB.
func (c *Consula) manage() {
	c.wg.Add(1)
	defer c.wg.Done()

	{
	mloop:
		for {
			select {
			case <-c.closer:
				break mloop

			case req, ok := <-c.nbr:
				if !ok {
					break mloop
				}

				err := AddBucket(c.db, req.Bucket)

				// TODO(alex): Decide if we should ignore request instead.
				// If we have no means of responding, ignore the request.
				if req.Response == nil {
					continue mloop
				}

				select {
				case req.Response <- err:
					break
				case <-time.After(2 * time.Second):
					// If response is not retrieve in 2 seconds, kill this.
					continue mloop
				}

			case req, ok := <-c.br:
				if !ok {
					break mloop
				}

				// If we have no means of responding, ignore the request.
				if req.Response == nil {
					continue mloop
				}

				total, err := GetSize(c.db, req.Bucket)

				select {
				case req.Response <- BucketSizeResponse{Size: total, Error: err}:
					break
				case <-time.After(2 * time.Second):
					// If response is not retrieve in 2 seconds, kill this.
					continue mloop
				}

			case req, ok := <-c.gr:
				if !ok {
					break mloop
				}

				// If we have no means of responding, ignore the request.
				if req.Response == nil {
					continue mloop
				}

				results, err := Get(c.db, req.Bucket, req.From, req.Total)

				select {
				case req.Response <- GetResponse{Events: results, Error: err}:
					break
				case <-time.After(2 * time.Second):
					// If response is not retrieve in 2 seconds, kill this.
					continue mloop
				}

			case req, ok := <-c.svr:
				if !ok {
					break mloop
				}

				err := Save(c.db, req.Bucket, req.Events)

				// TODO(alex): Decide if we should ignore request instead.
				// If we have no means of responding, ignore the request.
				if req.Response == nil {
					continue mloop
				}

				select {
				case req.Response <- err:
					break
				case <-time.After(2 * time.Second):
					// If response is not retrieve in 2 seconds, kill this.
					continue mloop

				}
			case <-time.After(1 * time.Second):
				// Do nothing
			}
		}
	}
}

// Close stops the Consula operations and closes the db.
func (c *Consula) Close() error {
	if c.closer == nil {
		return nil
	}

	// Nil the db as well.
	defer func() { c.db = nil }()

	close(c.closer)

	c.wg.Wait()

	return c.db.Close()
}

var eventBucket = []byte("events")

// Send delivers the giving event into the save request channel.
func (c *Consula) Send(ev event.Event) {
	if c.svr == nil {
		return
	}

	c.svr <- SaveRequest{
		Bucket: eventBucket,
		Events: []event.Event{ev},
	}
}
