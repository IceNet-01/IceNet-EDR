package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/icenet/edr-server/api"
	"github.com/icenet/edr-server/database"
	"github.com/icenet/edr-server/processor"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func main() {
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.InfoLevel)

	log.Info("Starting IceNet EDR Management Server")

	// Load configuration
	config := loadConfig()

	// Initialize database
	db, err := database.Initialize(config.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize event processor
	eventProcessor, err := processor.NewEventProcessor(db, config.NatsURL)
	if err != nil {
		log.Fatalf("Failed to initialize event processor: %v", err)
	}

	// Start event processor
	go eventProcessor.Start()

	// Initialize API server
	router := setupRouter(db, eventProcessor)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		log.Infof("Server listening on port %d", config.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Errorf("Server forced to shutdown: %v", err)
	}

	eventProcessor.Stop()

	log.Info("Server exited")
}

func setupRouter(db *database.Database, processor *processor.EventProcessor) *gin.Engine {
	router := gin.Default()

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// API v1
	v1 := router.Group("/api/v1")
	{
		// Agent endpoints
		agentAPI := api.NewAgentAPI(db, processor)
		agentGroup := v1.Group("/agent")
		{
			agentGroup.POST("/register", agentAPI.Register)
			agentGroup.POST("/heartbeat", agentAPI.Heartbeat)
			agentGroup.POST("/events", agentAPI.ReceiveEvents)
		}

		// Dashboard endpoints
		dashboardAPI := api.NewDashboardAPI(db)
		dashboardGroup := v1.Group("/dashboard")
		{
			dashboardGroup.GET("/overview", dashboardAPI.GetOverview)
			dashboardGroup.GET("/agents", dashboardAPI.GetAgents)
			dashboardGroup.GET("/agents/:id", dashboardAPI.GetAgent)
			dashboardGroup.GET("/events", dashboardAPI.GetEvents)
			dashboardGroup.GET("/events/:id", dashboardAPI.GetEvent)
			dashboardGroup.GET("/alerts", dashboardAPI.GetAlerts)
			dashboardGroup.GET("/threats", dashboardAPI.GetThreats)
		}

		// Action endpoints
		actionAPI := api.NewActionAPI(db, processor)
		actionGroup := v1.Group("/actions")
		{
			actionGroup.POST("/quarantine", actionAPI.QuarantineFile)
			actionGroup.POST("/terminate", actionAPI.TerminateProcess)
			actionGroup.POST("/block", actionAPI.BlockNetwork)
			actionGroup.POST("/isolate", actionAPI.IsolateHost)
		}
	}

	return router
}

type Config struct {
	Port        int
	DatabaseURL string
	NatsURL     string
	RedisURL    string
}

func loadConfig() *Config {
	return &Config{
		Port:        getEnvInt("PORT", 8443),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://icenet:password@localhost:5432/icenet_edr?sslmode=disable"),
		NatsURL:     getEnv("NATS_URL", "nats://localhost:4222"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intValue int
		fmt.Sscanf(value, "%d", &intValue)
		return intValue
	}
	return defaultValue
}
