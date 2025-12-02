package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/icenet/edr-server/database"
)

type DashboardAPI struct {
	db *database.Database
}

func NewDashboardAPI(db *database.Database) *DashboardAPI {
	return &DashboardAPI{db: db}
}

func (api *DashboardAPI) GetOverview(c *gin.Context) {
	stats, err := api.db.GetStatistics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get statistics"})
		return
	}

	c.JSON(http.StatusOK, stats)
}

func (api *DashboardAPI) GetAgents(c *gin.Context) {
	agents, err := api.db.GetAllAgents()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get agents"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agents": agents,
		"count":  len(agents),
	})
}

func (api *DashboardAPI) GetAgent(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	agent, err := api.db.GetAgent(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(http.StatusOK, agent)
}

func (api *DashboardAPI) GetEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	filters := make(map[string]interface{})
	if severity := c.Query("severity"); severity != "" {
		filters["severity"] = severity
	}
	if eventType := c.Query("event_type"); eventType != "" {
		filters["event_type"] = eventType
	}
	if agentID := c.Query("agent_id"); agentID != "" {
		id, err := uuid.Parse(agentID)
		if err == nil {
			filters["agent_id"] = id
		}
	}

	events, err := api.db.GetEvents(limit, offset, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get events"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"count":  len(events),
		"limit":  limit,
		"offset": offset,
	})
}

func (api *DashboardAPI) GetEvent(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event ID"})
		return
	}

	event, err := api.db.GetEventByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}

	c.JSON(http.StatusOK, event)
}

func (api *DashboardAPI) GetAlerts(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	filters := make(map[string]interface{})
	if severity := c.Query("severity"); severity != "" {
		filters["severity"] = severity
	}
	if status := c.Query("status"); status != "" {
		filters["status"] = status
	}

	alerts, err := api.db.GetAlerts(limit, offset, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get alerts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"count":  len(alerts),
		"limit":  limit,
		"offset": offset,
	})
}

func (api *DashboardAPI) GetThreats(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	filters := map[string]interface{}{
		"severity": "high",
	}

	alerts, err := api.db.GetAlerts(limit, offset, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get threats"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"threats": alerts,
		"count":   len(alerts),
		"limit":   limit,
		"offset":  offset,
	})
}
