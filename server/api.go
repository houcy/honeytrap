package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/dimfeld/httptreemux"
	"github.com/gorilla/websocket"
	"github.com/honeytrap/honeytrap/config"
	"github.com/honeytrap/honeytrap/director"
	"github.com/honeytrap/honeytrap/pushers/backends/bolt"
	"github.com/honeytrap/honeytrap/pushers/event"
)

//=============================================================================================================

// Contains the different buckets used
var (
	eventsBucket  = []byte(event.EventSensorName)
	sessionBucket = []byte(event.SessionSensorName)
	pingBucket    = []byte(event.PingSensorName)
)

//=============================================================================================================

// Honeycast defines a struct which exposes methods to handle api related service
// responses.
type Honeycast struct {
	*httptreemux.TreeMux
	Socket   *Socketcast
	Assets   http.Handler
	Config   *config.Config
	Director director.Director
	Manager  *director.ContainerConnections

	GetEventReqs   chan bolt.GetRequest
	SaveEventReqs  chan bolt.SaveRequest
	BucketSizeReqs chan bolt.BucketSizeResquest
	AddBucketReqs  chan bolt.NewBucketRequest
}

func (h *Honeycast) initRoutes() {

	// Register endpoints for events.
	h.TreeMux.Handle("GET", "/", h.Index)
	h.TreeMux.Handle("GET", "/events", h.Events)
	h.TreeMux.Handle("GET", "/sessions", h.Sessions)
	h.TreeMux.Handle("GET", "/ws", h.Socket.ServeHandle)

	// Register endpoints for metrics details
	h.TreeMux.Handle("GET", "/metrics/attackers", h.Attackers)
	h.TreeMux.Handle("GET", "/metrics/containers", h.Containers)

	// Register endpoints for container interaction details
	h.TreeMux.Handle("DELETE", "/containers/clients/:container_id", h.ContainerClientDelete)
	h.TreeMux.Handle("DELETE", "/containers/connections/:container_id", h.ContainerConnectionsDelete)
}

func (h *Honeycast) initEvents() {
	h.AddBucketReqs <- bolt.NewBucketRequest{
		Bucket: sessionBucket,
	}

	h.AddBucketReqs <- bolt.NewBucketRequest{
		Bucket: eventsBucket,
	}

	h.AddBucketReqs <- bolt.NewBucketRequest{
		Bucket: pingBucket,
	}

	h.AddBucketReqs <- bolt.NewBucketRequest{
		Bucket: []byte("events"),
	}

	h.AddBucketReqs <- bolt.NewBucketRequest{
		Bucket: []byte(event.DataSensorName),
	}

	h.AddBucketReqs <- bolt.NewBucketRequest{
		Bucket: []byte(event.ContainersSensorName),
	}

	h.AddBucketReqs <- bolt.NewBucketRequest{
		Bucket: []byte(event.ConnectionSensorName),
	}

	h.AddBucketReqs <- bolt.NewBucketRequest{
		Bucket: []byte(event.ServiceSensorName),
	}

	h.AddBucketReqs <- bolt.NewBucketRequest{
		Bucket: []byte(event.ErrorsSensorName),
	}
}

// Send delivers the underline provided messages and stores them into the underline
// Honeycast database for retrieval through the API.
func (h *Honeycast) Send(ev event.Event) {
	var containers, connections, data, services, pings, serrors, sessions, events []event.Event

	events = append(events, ev)

	sensor, ok := ev["sensor"].(string)
	if !ok {
		log.Error("Honeycast API : Event object has non string sensor value : %#q", ev)
		return
	}

	switch sensor {
	case event.SessionSensorName:
		sessions = append(sessions, ev)
	case event.PingSensorName:
		pings = append(pings, ev)
	case event.DataSensorName:
		data = append(data, ev)
	case event.ServiceSensorName:
		services = append(services, ev)
	case event.ContainersSensorName:
		containers = append(containers, ev)
	case event.ConnectionSensorName:
		connections = append(connections, ev)
	case event.ConnectionErrorSensorName, event.DataErrorSensorName:
		serrors = append(serrors, ev)
	}

	// Batch deliver both sessions and events data to all connected
	h.Socket.events <- events
	h.Socket.sessions <- sessions

	h.SaveEventReqs <- bolt.SaveRequest{
		Bucket: sessionBucket,
		Events: sessions,
	}

	h.SaveEventReqs <- bolt.SaveRequest{
		Events: events,
		Bucket: eventsBucket,
	}

	h.SaveEventReqs <- bolt.SaveRequest{
		Bucket: pingBucket,
		Events: pings,
	}

	h.SaveEventReqs <- bolt.SaveRequest{
		Bucket: []byte(event.DataSensorName),
		Events: data,
	}

	h.SaveEventReqs <- bolt.SaveRequest{
		Bucket: []byte(event.ContainersSensorName),
		Events: data,
	}

	h.SaveEventReqs <- bolt.SaveRequest{
		Bucket: []byte(event.ConnectionSensorName),
		Events: connections,
	}

	h.SaveEventReqs <- bolt.SaveRequest{
		Bucket: []byte(event.ServiceSensorName),
		Events: services,
	}

	h.SaveEventReqs <- bolt.SaveRequest{
		Bucket: []byte(event.ErrorsSensorName),
		Events: serrors,
	}
}

// ContainerClientDelete services the request to delete a giving containers client detail without
// affecting the existing connections.
func (h *Honeycast) ContainerClientDelete(w http.ResponseWriter, r *http.Request, params map[string]string) {
	if err := h.Manager.RemoveClient(params["container_id"]); err != nil {
		log.Error("Honeycast API : Operation Failed : %+q", err)
		http.Error(w, "Operation Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ContainerConnectionsDelete services the request to delete a giving containers client detail and
// related existing connections.
func (h *Honeycast) ContainerConnectionsDelete(w http.ResponseWriter, r *http.Request, params map[string]string) {
	if err := h.Manager.RemoveClientWithConns(params["container_id"]); err != nil {
		log.Error("Honeycast API : Operation Failed : %+q", err)
		http.Error(w, "Operation Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AttackerResponse defines the response delivered for requesting list of all
// current container users.
type AttackerResponse struct {
	Total     int                     `json:"total"`
	Attackers []director.ClientDetail `json:"attackers"`
}

// Attackers delivers metrics from the underlying API about specific users
// of the current running dataset.
func (h *Honeycast) Attackers(w http.ResponseWriter, r *http.Request, params map[string]string) {
	users := h.Manager.ListClients()

	response := AttackerResponse{
		Total:     len(users),
		Attackers: users,
	}

	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "\t")

	if err := encoder.Encode(response); err != nil {
		log.Error("Honeycast API : Operation Failed : %+q", err)
		http.Error(w, "Operation Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// ContainerResponse defines the response delivered for requesting list of all containers
// lunched.
type ContainerResponse struct {
	Total      int                        `json:"total"`
	Containers []director.ContainerDetail `json:"containers"`
}

// Containers delivers metrics from the underlying API about specific data related to containers
// started, stopped and running.
func (h *Honeycast) Containers(w http.ResponseWriter, r *http.Request, params map[string]string) {
	containers := h.Director.ListContainers()

	response := ContainerResponse{
		Total:      len(containers),
		Containers: containers,
	}

	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "\t")

	if err := encoder.Encode(response); err != nil {
		log.Error("Honeycast API : Operation Failed : %+q", err)
		http.Error(w, "Operation Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// Sessions handles response for all `/sessions` target endpoint and returns all giving push
// messages returns the slice of data.
func (h *Honeycast) Sessions(w http.ResponseWriter, r *http.Request, params map[string]string) {
	h.bucketFind(sessionBucket, w, r, params)
}

// Events handles response for all `/events` target endpoint and returns all giving events
// and expects a giving filter paramter which will be used to filter out the needed events.
func (h *Honeycast) Events(w http.ResponseWriter, r *http.Request, params map[string]string) {
	h.bucketFind(eventsBucket, w, r, params)
}

func (h *Honeycast) bucketFind(bucket []byte, w http.ResponseWriter, r *http.Request, params map[string]string) {
	resChan := make(chan bolt.BucketSizeResponse)

	h.BucketSizeReqs <- bolt.BucketSizeResquest{
		Bucket:   bucket,
		Response: resChan,
	}

	bucketResponse := <-resChan
	if bucketResponse.Error != nil {
		log.Error("Honeycast API : Operation Failed : %+q", bucketResponse.Error)
		http.Error(w, "Operation Failed: "+bucketResponse.Error.Error(), http.StatusInternalServerError)
		return
	}

	var req EventRequest

	if terr := json.NewDecoder(r.Body).Decode(&req); terr != nil {
		log.Error("Honeycast API : Invalid Request Object data: %+q", terr)
		http.Error(w, "Invalid Request Object data: "+terr.Error(), http.StatusInternalServerError)
		return
	}

	var res EventResponse
	res.Page = req.Page
	res.Total = bucketResponse.Size
	res.ResponsePerPage = req.ResponsePerPage

	resEventChan := make(chan bolt.GetResponse)

	if req.ResponsePerPage <= 0 || req.Page <= 0 {

		h.GetEventReqs <- bolt.GetRequest{
			From:     -1,
			Total:    -1,
			Bucket:   bucket,
			Response: resEventChan,
		}

		eventRes := <-resEventChan

		res.Events = eventRes.Events
		if eventRes.Error != nil {
			log.Error("Honeycast API : Invalid Response received : %+q", eventRes.Error)
			http.Error(w, "Invalid 'From' parameter: "+eventRes.Error.Error(), http.StatusInternalServerError)
			return
		}

	} else {
		length := req.ResponsePerPage * req.Page
		index := (length / 2)

		if req.Page > 1 {
			index++
		}

		h.GetEventReqs <- bolt.GetRequest{
			From:     index,
			Total:    length,
			Bucket:   bucket,
			Response: resEventChan,
		}

		eventRes := <-resEventChan

		if eventRes.Error != nil {
			log.Error("Honeycast API : Invalid Response received : %+q", eventRes.Error)
			http.Error(w, "Invalid 'From' parameter: "+eventRes.Error.Error(), http.StatusInternalServerError)
			return
		}

		{
			var filteredEvents []event.Event

			doTypeMatch := len(req.TypeFilters) != 0
			doSensorMatch := len(req.SensorFilters) != 0

			if doTypeMatch || doSensorMatch {

				for _, event := range eventRes.Events {

					eventType, ok := event["type"].(string)
					if !ok {
						log.Error("Honeycast API : Invalid Response received : %+q", eventRes.Error)
						http.Error(w, "Invalid 'Type' parameter, string allowed only: "+eventRes.Error.Error(), http.StatusInternalServerError)
						return
					}

					eventSensor, ok := event["sensor"].(string)
					if !ok {
						log.Error("Honeycast API : Invalid Response received : %+q", eventRes.Error)
						http.Error(w, "Invalid 'Type' parameter, string allowed only: "+eventRes.Error.Error(), http.StatusInternalServerError)
						return
					}

					var typeMatched bool
					var sensorMatched bool

					{
					typeFilterLoop:
						for _, tp := range req.TypeFilters {
							// If we match atleast one type then allow event event.
							if eventType == tp {
								typeMatched = true
								break typeFilterLoop
							}
						}

						// If there are type filters and event does not match, skip.
						if doTypeMatch && !typeMatched {
							continue
						}
					}

					{
					sensorFilterLoop:
						for _, tp := range req.SensorFilters {

							sensorRegExp, err := regexp.Compile(tp)
							if err != nil {
								log.Errorf("Honeycast API : Failed to creat match for %q : %+q", tp, err)
								continue sensorFilterLoop
							}

							// If we match atleast one type then allow event event.
							if sensorRegExp.MatchString(eventSensor) {
								sensorMatched = true
								break sensorFilterLoop
							}
						}

						// If there are sensor filters and event does not match, skip.
						if doSensorMatch && !sensorMatched {
							continue
						}

					}

					filteredEvents = append(filteredEvents, event)
				}

				res.Events = filteredEvents
			} else {
				res.Events = eventRes.Events
			}
		}

	}

	var bu bytes.Buffer
	if jserr := json.NewEncoder(&bu).Encode(res); jserr != nil {
		log.Error("Honeycast API : Invalid 'From' Param: %+q", jserr)
		http.Error(w, "Invalid 'From' parameter: "+jserr.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(bu.Bytes())
}

// Index handles the servicing of index based requests for the giving service.
func (h *Honeycast) Index(w http.ResponseWriter, r *http.Request, params map[string]string) {
	if h.Assets != nil {
		h.Assets.ServeHTTP(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

//=================================================================================

const (
	maxBufferSize       = 1024 * 1024
	maxPingPongInterval = 5 * time.Second
	maxPingPongWait     = (maxPingPongInterval * 9) / 10
)

type targetMessage struct {
	client  *websocket.Conn
	message []byte
	mtype   int
}

// Socketcast defines structure which exposes specific interface for interacting with a
// websocket structure.
type Socketcast struct {
	uprader      websocket.Upgrader
	GetEventReqs chan bolt.GetRequest
	clients      map[*websocket.Conn]bool
	newClients   chan *websocket.Conn
	closeClients chan *websocket.Conn
	events       chan []event.Event
	sessions     chan []event.Event
	close        chan struct{}
	data         chan targetMessage
	wg           sync.WaitGroup
	closed       bool
}

// NewSocketcast returns a new instance of a Socketcast.
func NewSocketcast(config *config.Config, gprs chan bolt.GetRequest, origins func(*http.Request) bool) *Socketcast {
	var socket Socketcast
	socket.GetEventReqs = gprs

	socket.uprader = websocket.Upgrader{
		ReadBufferSize:  maxBufferSize,
		WriteBufferSize: maxBufferSize,
		CheckOrigin:     origins,
	}

	socket.close = make(chan struct{}, 0)
	socket.data = make(chan targetMessage, 0)
	socket.events = make(chan []event.Event, 0)
	socket.clients = make(map[*websocket.Conn]bool)
	socket.sessions = make(chan []event.Event, 0)
	socket.newClients = make(chan *websocket.Conn, 0)
	socket.closeClients = make(chan *websocket.Conn, 0)

	// spin up the socket internal processes.
	go socket.manage()

	return &socket
}

// ServeHandle defines a method which implements the httptreemux.Handle to allow us easily,
// use the socket as a server to a giving httptreemux.Tree router.
func (socket *Socketcast) ServeHandle(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	socket.ServeHTTP(w, r)
}

// Close ends the internal routine of the Socket server.
func (socket *Socketcast) Close() error {
	if socket.closed {
		return errors.New("Already Closed")
	}

	close(socket.close)
	socket.closed = true

	socket.wg.Wait()

	return nil
}

// manage runs the loop to manage the connections and message delivery processes of the
// Socketcast instance.
func (socket *Socketcast) manage() {
	socket.wg.Add(1)
	defer socket.wg.Done()

	ticker := time.NewTicker(maxPingPongInterval)

	{
	mloop:
		for {
			select {
			case <-ticker.C:

				for client := range socket.clients {
					client.WriteMessage(websocket.PingMessage, nil)
				}

			case newConn, ok := <-socket.newClients:
				if !ok {
					ticker.Stop()
					break mloop
				}

				socket.clients[newConn] = true

			case message, ok := <-socket.data:
				if !ok {
					ticker.Stop()
					break mloop
				}

				if err := handleMessage(socket.GetEventReqs, message.message, message.client); err != nil {
					log.Error("Honeycast API : Failed to process message : %+q : %+q", message, err)
				}

			case closeConn, ok := <-socket.closeClients:
				if !ok {
					ticker.Stop()
					break mloop
				}

				delete(socket.clients, closeConn)

				// Close the connection as well.
				closeConn.WriteMessage(websocket.CloseMessage, nil)
				closeConn.Close()

			case newEvents, ok := <-socket.events:
				if !ok {
					ticker.Stop()
					break mloop
				}

				for client := range socket.clients {
					err := deliverMessage(Message{
						Type:    NewEvents,
						Payload: newEvents,
					}, client)

					if err != nil {
						log.Error("Honeycast API : Failed to deliver events : %+q : %+q", client.RemoteAddr(), err)
					}
				}

			case newEvents, ok := <-socket.sessions:
				if !ok {
					ticker.Stop()
					break mloop
				}

				for client := range socket.clients {
					err := deliverMessage(Message{
						Type:    NewSessions,
						Payload: newEvents,
					}, client)

					if err != nil {
						log.Error("Honeycast API : Failed to deliver events : %+q : %+q", client.RemoteAddr(), err)
					}
				}
			}
		}
	}
}

// ServeHTTP serves and transforms incoming request into websocket connections.
func (socket *Socketcast) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := socket.uprader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("Honeycast API : Failed to uprade request : %+q", err)
		http.Error(w, "Failed to upgrade request", http.StatusInternalServerError)
		return
	}

	conn.SetPongHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(maxPingPongWait))
		return nil
	})

	// Register new connection into our client map and routine.
	socket.newClients <- conn

	{
		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				// Error possibly occured, so we need to stop here.
				log.Error("Honeycast API : Connection read failed abruptly : %+q", err)
				socket.closeClients <- conn
				return
			}

			conn.SetReadDeadline(time.Time{})

			switch messageType {
			case websocket.CloseMessage:
				socket.closeClients <- conn
				return
			}

			socket.data <- targetMessage{
				client:  conn,
				message: message,
				mtype:   messageType,
			}
		}
	}

}

//=============================================================================================

// handleMessage defines a central method which provides the entry point which is used
// to respond to new messages.
func handleMessage(hc chan bolt.GetRequest, message []byte, conn *websocket.Conn) error {
	var newMessage Message

	if err := json.NewDecoder(bytes.NewBuffer(message)).Decode(&newMessage); err != nil {
		log.Errorf("Honeycast API : Failed to decode message : %+q", err)
		return err
	}

	// We initially will only handle just two requests of getter types.
	// TODO: Handle NewSessions and NewEvents somewhere else.
	switch newMessage.Type {
	case FetchEvents:
		var message Message
		message.Type = FetchEventsReply

		resChan := make(chan bolt.GetResponse)

		hc <- bolt.GetRequest{
			From:     -1,
			Total:    -1,
			Response: resChan,
			Bucket:   eventsBucket,
		}

		bucketResponse := <-resChan

		if bucketResponse.Error != nil {
			log.Error("Honeycast API : Invalid Response with Sessions Retrieval : %+q", bucketResponse.Error)

			return deliverMessage(Message{
				Type:    ErrorResponse,
				Payload: bucketResponse.Error.Error(),
			}, conn)
		}

		message.Payload = bucketResponse.Events

		return deliverMessage(message, conn)

	case FetchSessions:
		var message Message
		message.Type = FetchSessionsReply

		resChan := make(chan bolt.GetResponse)

		hc <- bolt.GetRequest{
			From:     -1,
			Total:    -1,
			Response: resChan,
			Bucket:   sessionBucket,
		}

		bucketResponse := <-resChan

		if bucketResponse.Error != nil {
			log.Error("Honeycast API : Invalid Response with Sessions Retrieval : %+q", bucketResponse.Error)

			return deliverMessage(Message{
				Type:    ErrorResponse,
				Payload: bucketResponse.Error.Error(),
			}, conn)
		}

		return deliverMessage(message, conn)

	default:
		return deliverMessage(Message{
			Type:    ErrorResponse,
			Payload: "Unknown Request Type",
		}, conn)
	}
}

// deliverMessage defines a method which handles the delivery of a message to a giving
// websocket.Conn.
func deliverMessage(message Message, conn *websocket.Conn) error {
	var bu bytes.Buffer

	if err := json.NewEncoder(&bu).Encode(message); err != nil {
		log.Errorf("Honeycast API : Failed to decode message : %+q", err)
		return err
	}

	return conn.WriteMessage(websocket.BinaryMessage, bu.Bytes())
}

//=====================================================================================================

// Contains values for use.
const (
	ResponsePerPageHeader = "response_per_page"
	PageHeader            = "page"
)

// EventResponse defines a struct which is sent a request type used to respond to
// given requests.
type EventResponse struct {
	ResponsePerPage int           `json:"responser_per_page"`
	Page            int           `json:"page"`
	Total           int           `json:"total"`
	Events          []event.Event `json:"events"`
}

// EventRequest defines a struct which receives a request type used to retrieve
// given requests type.
type EventRequest struct {
	ResponsePerPage int      `json:"responser_per_page"`
	Page            int      `json:"page"`
	TypeFilters     []string `json:"types"`
	SensorFilters   []string `json:"sensors"`
}
