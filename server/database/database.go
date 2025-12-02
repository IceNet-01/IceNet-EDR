package database

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Database struct {
	*gorm.DB
}

// Agent represents a registered EDR agent
type Agent struct {
	ID            uuid.UUID `gorm:"type:uuid;primary_key"`
	Hostname      string    `gorm:"index"`
	OSType        string
	OSVersion     string
	AgentVersion  string
	Status        string `gorm:"index"`
	LastHeartbeat time.Time
	IPAddress     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Event represents a security event
type Event struct {
	ID            uuid.UUID `gorm:"type:uuid;primary_key"`
	AgentID       uuid.UUID `gorm:"type:uuid;index"`
	EventType     string    `gorm:"index"`
	Severity      string    `gorm:"index"`
	Timestamp     time.Time `gorm:"index"`
	Hostname      string
	OSType        string
	EventData     string `gorm:"type:jsonb"`
	DetectionData string `gorm:"type:jsonb"`
	CreatedAt     time.Time
}

// Alert represents a threat alert
type Alert struct {
	ID              uuid.UUID `gorm:"type:uuid;primary_key"`
	EventID         uuid.UUID `gorm:"type:uuid;index"`
	AgentID         uuid.UUID `gorm:"type:uuid;index"`
	Severity        string    `gorm:"index"`
	MalwareFamily   string
	Confidence      float32
	Description     string
	Status          string `gorm:"index"` // new, investigating, resolved
	AssignedTo      string
	MitreTactics    string `gorm:"type:jsonb"`
	MitreTechniques string `gorm:"type:jsonb"`
	Indicators      string `gorm:"type:jsonb"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Action represents a response action taken
type Action struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key"`
	AgentID     uuid.UUID `gorm:"type:uuid;index"`
	AlertID     uuid.UUID `gorm:"type:uuid;index"`
	ActionType  string
	Status      string `gorm:"index"` // pending, success, failed
	Reason      string
	ActionData  string `gorm:"type:jsonb"`
	ExecutedBy  string
	ExecutedAt  time.Time
	CompletedAt *time.Time
	Result      string
	CreatedAt   time.Time
}

// ThreatIndicator represents threat intelligence
type ThreatIndicator struct {
	ID            uuid.UUID `gorm:"type:uuid;primary_key"`
	IndicatorType string    `gorm:"index"`
	Value         string    `gorm:"index"`
	MalwareFamily string
	Confidence    float32
	Source        string
	FirstSeen     time.Time
	LastSeen      time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func Initialize(databaseURL string) (*Database, error) {
	db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto-migrate schema
	if err := db.AutoMigrate(
		&Agent{},
		&Event{},
		&Alert{},
		&Action{},
		&ThreatIndicator{},
	); err != nil {
		return nil, err
	}

	return &Database{db}, nil
}

// Agent operations
func (db *Database) CreateAgent(agent *Agent) error {
	return db.Create(agent).Error
}

func (db *Database) GetAgent(id uuid.UUID) (*Agent, error) {
	var agent Agent
	err := db.Where("id = ?", id).First(&agent).Error
	return &agent, err
}

func (db *Database) UpdateAgentHeartbeat(id uuid.UUID) error {
	return db.Model(&Agent{}).Where("id = ?", id).Updates(map[string]interface{}{
		"last_heartbeat": time.Now(),
		"status":         "online",
	}).Error
}

func (db *Database) GetAllAgents() ([]Agent, error) {
	var agents []Agent
	err := db.Find(&agents).Error
	return agents, err
}

// Event operations
func (db *Database) CreateEvent(event *Event) error {
	return db.Create(event).Error
}

func (db *Database) GetEvents(limit, offset int, filters map[string]interface{}) ([]Event, error) {
	var events []Event
	query := db.Model(&Event{})

	for key, value := range filters {
		query = query.Where(key+" = ?", value)
	}

	err := query.Order("timestamp DESC").Limit(limit).Offset(offset).Find(&events).Error
	return events, err
}

func (db *Database) GetEventByID(id uuid.UUID) (*Event, error) {
	var event Event
	err := db.Where("id = ?", id).First(&event).Error
	return &event, err
}

// Alert operations
func (db *Database) CreateAlert(alert *Alert) error {
	return db.Create(alert).Error
}

func (db *Database) GetAlerts(limit, offset int, filters map[string]interface{}) ([]Alert, error) {
	var alerts []Alert
	query := db.Model(&Alert{})

	for key, value := range filters {
		query = query.Where(key+" = ?", value)
	}

	err := query.Order("created_at DESC").Limit(limit).Offset(offset).Find(&alerts).Error
	return alerts, err
}

func (db *Database) UpdateAlertStatus(id uuid.UUID, status string) error {
	return db.Model(&Alert{}).Where("id = ?", id).Update("status", status).Error
}

// Action operations
func (db *Database) CreateAction(action *Action) error {
	return db.Create(action).Error
}

func (db *Database) UpdateActionStatus(id uuid.UUID, status, result string) error {
	now := time.Now()
	return db.Model(&Action{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":       status,
		"result":       result,
		"completed_at": &now,
	}).Error
}

// Threat intelligence operations
func (db *Database) CreateThreatIndicator(indicator *ThreatIndicator) error {
	return db.Create(indicator).Error
}

func (db *Database) GetThreatIndicator(indicatorType, value string) (*ThreatIndicator, error) {
	var indicator ThreatIndicator
	err := db.Where("indicator_type = ? AND value = ?", indicatorType, value).First(&indicator).Error
	return &indicator, err
}

// Statistics
func (db *Database) GetStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count agents
	var agentCount int64
	db.Model(&Agent{}).Count(&agentCount)
	stats["total_agents"] = agentCount

	// Count online agents
	var onlineCount int64
	db.Model(&Agent{}).Where("status = ?", "online").Count(&onlineCount)
	stats["online_agents"] = onlineCount

	// Count events (last 24 hours)
	var eventCount int64
	db.Model(&Event{}).Where("timestamp > ?", time.Now().Add(-24*time.Hour)).Count(&eventCount)
	stats["events_24h"] = eventCount

	// Count alerts
	var alertCount int64
	db.Model(&Alert{}).Where("status != ?", "resolved").Count(&alertCount)
	stats["active_alerts"] = alertCount

	// Count critical alerts
	var criticalCount int64
	db.Model(&Alert{}).Where("severity = ? AND status != ?", "critical", "resolved").Count(&criticalCount)
	stats["critical_alerts"] = criticalCount

	return stats, nil
}
