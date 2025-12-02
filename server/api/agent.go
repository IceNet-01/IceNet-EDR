package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/icenet/edr-server/database"
	"github.com/icenet/edr-server/processor"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

type AgentAPI struct {
	db        *database.Database
	processor *processor.EventProcessor
}

func NewAgentAPI(db *database.Database, processor *processor.EventProcessor) *AgentAPI {
	return &AgentAPI{
		db:        db,
		processor: processor,
	}
}

type RegisterRequest struct {
	AgentID      string `json:"agent_id"`
	Hostname     string `json:"hostname"`
	OSType       string `json:"os_type"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

type RegisterResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func (api *AgentAPI) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	// Check if agent already exists
	existingAgent, err := api.db.GetAgent(agentID)
	if err == nil && existingAgent != nil {
		// Update existing agent
		log.Infof("Agent re-registering: %s (%s)", req.Hostname, agentID)
	} else {
		// Create new agent
		agent := &database.Agent{
			ID:            agentID,
			Hostname:      req.Hostname,
			OSType:        req.OSType,
			OSVersion:     req.OSVersion,
			AgentVersion:  req.AgentVersion,
			Status:        "online",
			LastHeartbeat: time.Now(),
			IPAddress:     c.ClientIP(),
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		if err := api.db.CreateAgent(agent); err != nil {
			log.Errorf("Failed to create agent: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register agent"})
			return
		}

		log.Infof("New agent registered: %s (%s)", req.Hostname, agentID)
	}

	c.JSON(http.StatusOK, RegisterResponse{
		Success: true,
		Message: "Agent registered successfully",
	})
}

type HeartbeatRequest struct {
	AgentID         string  `json:"agent_id"`
	Hostname        string  `json:"hostname"`
	Status          string  `json:"status"`
	CPUUsage        float32 `json:"cpu_usage"`
	MemoryUsageMB   uint32  `json:"memory_usage_mb"`
	EventsProcessed uint64  `json:"events_processed"`
	ThreatsDetected uint64  `json:"threats_detected"`
}

func (api *AgentAPI) Heartbeat(c *gin.Context) {
	var req HeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	// Update agent heartbeat
	if err := api.db.UpdateAgentHeartbeat(agentID); err != nil {
		log.Errorf("Failed to update agent heartbeat: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update heartbeat"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
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

func (api *AgentAPI) ReceiveEvents(c *gin.Context) {
	var events []EventMessage
	if err := c.ShouldBindJSON(&events); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Infof("Received %d events", len(events))

	// Process events asynchronously
	go func() {
		for _, event := range events {
			if err := api.processor.ProcessEvent(&event); err != nil {
				log.Errorf("Failed to process event: %v", err)
			}
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": "events received",
		"count":   len(events),
	})
}
