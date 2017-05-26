package slack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/pushers/message"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("honeytrap:channels:slack")

// APIConfig defines a struct which holds configuration field values used by the
// MessageChannel for it's message delivery to the slack channel API.
type APIConfig struct {
	Host  string `toml:"host"`
	Token string `toml:"token"`
}

// MessageChannel provides a struct which holds the configured means by which
// slack notifications are sent into giving slack groups and channels.
type MessageChannel struct {
	client    *http.Client
	apiconfig APIConfig
}

// New returns a new instance of a MessageChannel.
func New(api APIConfig) MessageChannel {
	return MessageChannel{
		apiconfig: api,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 5,
			},
			Timeout: time.Duration(20) * time.Second,
		},
	}
}

// NewWith defines a function to return a pushers.Channel which delivers
// new messages to a giving underline slack channel defined by the configuration
// retrieved from the giving toml.Primitive.
func NewWith(meta toml.MetaData, data toml.Primitive) (pushers.Channel, error) {
	var apiconfig APIConfig

	if err := meta.PrimitiveDecode(data, &apiconfig); err != nil {
		return nil, err
	}

	if apiconfig.Host == "" {
		return nil, errors.New("slack.APIConfig Invalid: Host can not be empty")
	}

	if apiconfig.Token == "" {
		return nil, errors.New("slack.APIConfig Invalid: Token can not be empty")
	}

	return New(apiconfig), nil
}

func init() {
	pushers.RegisterBackend("slack", NewWith)
}

// Send delivers the giving push messages to the required slack channel.
// TODO: Ask if Send shouldnt return an error to allow proper delivery validation.
func (mc MessageChannel) Send(messages []message.PushMessage) {
	for _, message := range messages {

		//Attempt to encode message body first and if failed, log and continue.
		messageBuffer := new(bytes.Buffer)
		if err := json.NewEncoder(messageBuffer).Encode(message.Data); err != nil {
			log.Errorf("SlackMessageChannel: Error encoding data: %q", err.Error())
			continue
		}

		// Create the appropriate fields for the giving slack message.
		var fields []newSlackField

		fields = append(fields, newSlackField{
			Title: "Sensor",
			Value: message.Sensor,
			Short: true,
		})

		fields = append(fields, newSlackField{
			Title: "Category",
			Value: message.Category,
			Short: true,
		})

		fields = append(fields, newSlackField{
			Title: "Session ID",
			Value: message.SessionID,
			Short: true,
		})

		fields = append(fields, newSlackField{
			Title: "Container ID",
			Value: message.ContainerID,
			Short: true,
		})

		var slackMessage newSlackMessage
		slackMessage.Text = fmt.Sprintf("New Sensor Message from %q with Category %q", message.Sensor, message.Category)
		slackMessage.Attachments = append(slackMessage.Attachments, newSlackAttachment{
			Title:    "Sensor Data",
			Author:   "HoneyTrap",
			Fields:   fields,
			Text:     string(messageBuffer.Bytes()),
			Fallback: fmt.Sprintf("New SensorMessage (Sensor: %q, Category: %q, Session: %q, Container: %q). Check Slack for more", message.Sensor, message.Category, message.SessionID, message.ContainerID),
		})

		slackMessageBuffer := new(bytes.Buffer)
		if err := json.NewEncoder(slackMessageBuffer).Encode(slackMessage); err != nil {
			log.Errorf("SlackMessageChannel: Error encoding new SlackMessage: %+q", err)
			continue
		}

		reqURL := fmt.Sprintf("%s/%s", mc.apiconfig.Host, mc.apiconfig.Token)
		req, err := http.NewRequest("POST", reqURL, slackMessageBuffer)
		if err != nil {
			log.Errorf("SlackMessageChannel: Error while creating new request object: %+q", err)
			continue
		}

		req.Header.Set("Content-Type", "application/json")

		res, err := mc.client.Do(req)
		if err != nil {
			log.Errorf("SlackMessageChannel: Error while making request to endpoint(%q): %q", reqURL, err.Error())
			continue
		}

		// Though we expect slack not to deliver any messages to us but to be safe
		// discard and close body.
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()

		if res.StatusCode != http.StatusCreated {
			log.Errorf("SlackMessageChannel: API Response with unexpected Status Code[%d] to endpoint: %q", res.StatusCode, reqURL)
			continue
		}
	}
}

type newSlackMessage struct {
	Text        string               `json:"text"`
	Channel     string               `json:"channel"`
	Attachments []newSlackAttachment `json:"attachments"`
}

type newSlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type newSlackAttachment struct {
	Title     string          `json:"title"`
	Author    string          `json:"author_name,omitempty"`
	Fallback  string          `json:"fallback,omitempty"`
	Fields    []newSlackField `json:"fields"`
	Text      string          `json:"text"`
	Timestamp int64           `json:"ts"`
}