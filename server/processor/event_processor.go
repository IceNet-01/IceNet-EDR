package processor

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/icenet/edr-server/database"
	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

type EventProcessor struct {
	db   *database.Database
	nats *nats.Conn
}

func NewEventProcessor(db *database.Database, natsURL string) (*EventProcessor, error) {
	nc, err := nats.Connect(natsURL)
	if err != nil {
		return nil, err
	}

	return &EventProcessor{
		db:   db,
		nats: nc,
	}, nil
}

func (ep *EventProcessor) Start() {
	log.Info("Event processor started")
	// Subscribe to event topics
	ep.nats.Subscribe("events.security", ep.handleSecurityEvent)
	ep.nats.Subscribe("events.alerts", ep.handleAlert)
}

func (ep *EventProcessor) Stop() {
	ep.nats.Close()
	log.Info("Event processor stopped")
}

type EventMessage struct {
	EventID   string                 `json:"event_id"`
	AgentID   string                 `json:"agent_id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	Severity  string                 `json:"severity"`
	Hostname  string                 `json:"hostname"`
	OSType    string                 `json:"os_type"`
	EventData map[string]interface{} `json:"event_data"`
	Detection *DetectionData         `json:"detection,omitempty"`
}

type DetectionData struct {
	DetectionID     string   `json:"detection_id"`
	DetectionType   string   `json:"detection_type"`
	MalwareFamily   string   `json:"malware_family,omitempty"`
	Confidence      float32  `json:"confidence"`
	Description     string   `json:"description"`
	MitreTactics    []string `json:"mitre_tactics"`
	MitreTechniques []string `json:"mitre_techniques"`
	Indicators      []string `json:"indicators"`
}

func (ep *EventProcessor) ProcessEvent(eventMsg *EventMessage) error {
	eventID, err := uuid.Parse(eventMsg.EventID)
	if err != nil {
		log.Errorf("Invalid event ID: %v", err)
		return err
	}

	agentID, err := uuid.Parse(eventMsg.AgentID)
	if err != nil {
		log.Errorf("Invalid agent ID: %v", err)
		return err
	}

	// Convert event data to JSON
	eventDataJSON, err := json.Marshal(eventMsg.EventData)
	if err != nil {
		log.Errorf("Failed to marshal event data: %v", err)
		return err
	}

	// Convert detection data to JSON
	var detectionDataJSON []byte
	if eventMsg.Detection != nil {
		detectionDataJSON, err = json.Marshal(eventMsg.Detection)
		if err != nil {
			log.Errorf("Failed to marshal detection data: %v", err)
			return err
		}
	}

	// Store event in database
	event := &database.Event{
		ID:            eventID,
		AgentID:       agentID,
		EventType:     eventMsg.EventType,
		Severity:      eventMsg.Severity,
		Timestamp:     eventMsg.Timestamp,
		Hostname:      eventMsg.Hostname,
		OSType:        eventMsg.OSType,
		EventData:     string(eventDataJSON),
		DetectionData: string(detectionDataJSON),
		CreatedAt:     time.Now(),
	}

	if err := ep.db.CreateEvent(event); err != nil {
		log.Errorf("Failed to store event: %v", err)
		return err
	}

	// If event has detection, create alert
	if eventMsg.Detection != nil {
		if err := ep.createAlert(event, eventMsg.Detection); err != nil {
			log.Errorf("Failed to create alert: %v", err)
		}
	}

	// Publish to NATS for real-time notifications
	ep.publishEvent(eventMsg)

	return nil
}

func (ep *EventProcessor) createAlert(event *database.Event, detection *DetectionData) error {
	tacticJSON, _ := json.Marshal(detection.MitreTactics)
	techniqueJSON, _ := json.Marshal(detection.MitreTechniques)
	indicatorJSON, _ := json.Marshal(detection.Indicators)

	alert := &database.Alert{
		ID:              uuid.New(),
		EventID:         event.ID,
		AgentID:         event.AgentID,
		Severity:        event.Severity,
		MalwareFamily:   detection.MalwareFamily,
		Confidence:      detection.Confidence,
		Description:     detection.Description,
		Status:          "new",
		MitreTactics:    string(tacticJSON),
		MitreTechniques: string(techniqueJSON),
		Indicators:      string(indicatorJSON),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := ep.db.CreateAlert(alert); err != nil {
		return err
	}

	log.Infof("Alert created: %s - %s", alert.ID, alert.Description)

	// Publish alert notification
	alertJSON, _ := json.Marshal(alert)
	ep.nats.Publish("alerts.new", alertJSON)

	return nil
}

func (ep *EventProcessor) publishEvent(event *EventMessage) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		log.Errorf("Failed to marshal event for publishing: %v", err)
		return
	}

	topic := "events." + event.EventType
	ep.nats.Publish(topic, eventJSON)
}

func (ep *EventProcessor) handleSecurityEvent(msg *nats.Msg) {
	var event EventMessage
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		log.Errorf("Failed to unmarshal security event: %v", err)
		return
	}

	ep.ProcessEvent(&event)
}

func (ep *EventProcessor) handleAlert(msg *nats.Msg) {
	log.Info("Alert notification received")
	// Handle alert notifications (e.g., send to webhook, email, etc.)
}
