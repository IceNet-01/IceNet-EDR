package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/icenet/edr-server/database"
	"github.com/icenet/edr-server/processor"
)

type ActionAPI struct {
	db        *database.Database
	processor *processor.EventProcessor
}

func NewActionAPI(db *database.Database, processor *processor.EventProcessor) *ActionAPI {
	return &ActionAPI{
		db:        db,
		processor: processor,
	}
}

type QuarantineRequest struct {
	AgentID string `json:"agent_id" binding:"required"`
	Path    string `json:"path" binding:"required"`
	Reason  string `json:"reason" binding:"required"`
}

func (api *ActionAPI) QuarantineFile(c *gin.Context) {
	var req QuarantineRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	action := &database.Action{
		ID:         uuid.New(),
		AgentID:    agentID,
		ActionType: "quarantine_file",
		Status:     "pending",
		Reason:     req.Reason,
		ActionData: `{"path":"` + req.Path + `"}`,
		ExecutedBy: "admin",
		ExecutedAt: time.Now(),
		CreatedAt:  time.Now(),
	}

	if err := api.db.CreateAction(action); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create action"})
		return
	}

	// TODO: Send command to agent
	log.Infof("Quarantine action created for agent %s: %s", agentID, req.Path)

	c.JSON(http.StatusOK, gin.H{
		"action_id": action.ID,
		"status":    "pending",
	})
}

type TerminateProcessRequest struct {
	AgentID   string `json:"agent_id" binding:"required"`
	ProcessID uint32 `json:"process_id" binding:"required"`
	Reason    string `json:"reason" binding:"required"`
}

func (api *ActionAPI) TerminateProcess(c *gin.Context) {
	var req TerminateProcessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	action := &database.Action{
		ID:         uuid.New(),
		AgentID:    agentID,
		ActionType: "terminate_process",
		Status:     "pending",
		Reason:     req.Reason,
		ExecutedBy: "admin",
		ExecutedAt: time.Now(),
		CreatedAt:  time.Now(),
	}

	if err := api.db.CreateAction(action); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create action"})
		return
	}

	log.Infof("Terminate process action created for agent %s: PID %d", agentID, req.ProcessID)

	c.JSON(http.StatusOK, gin.H{
		"action_id": action.ID,
		"status":    "pending",
	})
}

type BlockNetworkRequest struct {
	AgentID string `json:"agent_id" binding:"required"`
	Address string `json:"address" binding:"required"`
	Port    uint16 `json:"port" binding:"required"`
	Reason  string `json:"reason" binding:"required"`
}

func (api *ActionAPI) BlockNetwork(c *gin.Context) {
	var req BlockNetworkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	action := &database.Action{
		ID:         uuid.New(),
		AgentID:    agentID,
		ActionType: "block_network",
		Status:     "pending",
		Reason:     req.Reason,
		ExecutedBy: "admin",
		ExecutedAt: time.Now(),
		CreatedAt:  time.Now(),
	}

	if err := api.db.CreateAction(action); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create action"})
		return
	}

	log.Infof("Block network action created for agent %s: %s:%d", agentID, req.Address, req.Port)

	c.JSON(http.StatusOK, gin.H{
		"action_id": action.ID,
		"status":    "pending",
	})
}

type IsolateHostRequest struct {
	AgentID string `json:"agent_id" binding:"required"`
	Reason  string `json:"reason" binding:"required"`
}

func (api *ActionAPI) IsolateHost(c *gin.Context) {
	var req IsolateHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	action := &database.Action{
		ID:         uuid.New(),
		AgentID:    agentID,
		ActionType: "isolate_host",
		Status:     "pending",
		Reason:     req.Reason,
		ExecutedBy: "admin",
		ExecutedAt: time.Now(),
		CreatedAt:  time.Now(),
	}

	if err := api.db.CreateAction(action); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create action"})
		return
	}

	log.Infof("Isolate host action created for agent %s", agentID)

	c.JSON(http.StatusOK, gin.H{
		"action_id": action.ID,
		"status":    "pending",
	})
}
