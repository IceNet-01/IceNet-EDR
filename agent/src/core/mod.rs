use anyhow::Result;
use dashmap::DashMap;
use icenet_models::*;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use crate::config::Config;
use crate::communication::ServerConnection;
use crate::monitors::{FileMonitor, ProcessMonitor, NetworkMonitor};
use crate::detection::DetectionEngine;
use crate::response::ResponseHandler;

pub struct Agent {
    config: Arc<Config>,
    server_connection: Arc<ServerConnection>,
    detection_engine: Arc<DetectionEngine>,
    response_handler: Arc<ResponseHandler>,
    event_tx: mpsc::UnboundedSender<Event>,
    event_rx: mpsc::UnboundedReceiver<Event>,
    state: Arc<AgentState>,
}

pub struct AgentState {
    pub events_processed: std::sync::atomic::AtomicU64,
    pub threats_detected: std::sync::atomic::AtomicU64,
    pub start_time: std::time::Instant,
    pub quarantined_files: DashMap<String, QuarantineInfo>,
}

#[derive(Debug, Clone)]
pub struct QuarantineInfo {
    pub original_path: String,
    pub quarantine_path: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub reason: String,
}

impl Agent {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing IceNet EDR Agent");

        let config = Arc::new(config);
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Initialize components
        let server_connection = Arc::new(ServerConnection::new(config.clone()).await?);
        let detection_engine = Arc::new(DetectionEngine::new(config.clone()).await?);
        let response_handler = Arc::new(ResponseHandler::new(config.clone())?);

        let state = Arc::new(AgentState {
            events_processed: std::sync::atomic::AtomicU64::new(0),
            threats_detected: std::sync::atomic::AtomicU64::new(0),
            start_time: std::time::Instant::now(),
            quarantined_files: DashMap::new(),
        });

        info!("Agent initialized successfully");

        Ok(Self {
            config,
            server_connection,
            detection_engine,
            response_handler,
            event_tx,
            event_rx,
            state,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Starting IceNet EDR Agent");

        // Register with server
        self.register_with_server().await?;

        // Start monitoring tasks
        let mut tasks = vec![];

        // File system monitor
        if self.config.agent.monitoring.file_system {
            let monitor = FileMonitor::new(self.config.clone(), self.event_tx.clone())?;
            tasks.push(tokio::spawn(async move {
                if let Err(e) = monitor.run().await {
                    error!("File monitor error: {}", e);
                }
            }));
        }

        // Process monitor
        if self.config.agent.monitoring.processes {
            let monitor = ProcessMonitor::new(self.config.clone(), self.event_tx.clone())?;
            tasks.push(tokio::spawn(async move {
                if let Err(e) = monitor.run().await {
                    error!("Process monitor error: {}", e);
                }
            }));
        }

        // Network monitor
        if self.config.agent.monitoring.network {
            let monitor = NetworkMonitor::new(self.config.clone(), self.event_tx.clone())?;
            tasks.push(tokio::spawn(async move {
                if let Err(e) = monitor.run().await {
                    error!("Network monitor error: {}", e);
                }
            }));
        }

        // Event processing loop
        let event_processor = self.process_events();
        tasks.push(tokio::spawn(event_processor));

        // Heartbeat task
        let heartbeat_task = self.send_heartbeat();
        tasks.push(tokio::spawn(heartbeat_task));

        // Wait for all tasks
        for task in tasks {
            if let Err(e) = task.await {
                error!("Task error: {}", e);
            }
        }

        Ok(())
    }

    async fn register_with_server(&self) -> Result<()> {
        info!("Registering with server");

        let hostname = hostname::get()?
            .to_string_lossy()
            .to_string();

        let os_type = if cfg!(windows) {
            OsType::Windows
        } else if cfg!(target_os = "macos") {
            OsType::MacOS
        } else {
            OsType::Linux
        };

        self.server_connection.register(
            self.config.agent.agent_id,
            hostname,
            os_type,
        ).await?;

        info!("Successfully registered with server");
        Ok(())
    }

    async fn process_events(mut self) -> Result<()> {
        info!("Starting event processor");

        let mut event_batch = Vec::with_capacity(100);
        let batch_interval = tokio::time::Duration::from_secs(5);
        let mut batch_timer = tokio::time::interval(batch_interval);

        loop {
            tokio::select! {
                Some(event) = self.event_rx.recv() => {
                    // Increment counter
                    self.state.events_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Run through detection engine
                    let analyzed_event = self.detection_engine.analyze(event).await?;

                    // Check if threat detected
                    if analyzed_event.detection.is_some() {
                        self.state.threats_detected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!("Threat detected: {:?}", analyzed_event);

                        // Handle threat response
                        self.response_handler.handle_threat(&analyzed_event).await?;
                    }

                    // Add to batch
                    event_batch.push(analyzed_event);

                    // Send immediately if batch is full
                    if event_batch.len() >= 100 {
                        self.server_connection.send_events(event_batch.clone()).await?;
                        event_batch.clear();
                    }
                }
                _ = batch_timer.tick() => {
                    // Send batch on timer
                    if !event_batch.is_empty() {
                        self.server_connection.send_events(event_batch.clone()).await?;
                        event_batch.clear();
                    }
                }
            }
        }
    }

    async fn send_heartbeat(self) -> Result<()> {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(self.config.agent.update_interval_secs)
        );

        loop {
            interval.tick().await;

            let status = self.get_status();
            if let Err(e) = self.server_connection.send_heartbeat(status).await {
                error!("Failed to send heartbeat: {}", e);
            }
        }
    }

    fn get_status(&self) -> AgentStatus {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let os_type = if cfg!(windows) {
            OsType::Windows
        } else if cfg!(target_os = "macos") {
            OsType::MacOS
        } else {
            OsType::Linux
        };

        AgentStatus {
            agent_id: self.config.agent.agent_id,
            hostname,
            os_type,
            os_version: sys_info::os_release().unwrap_or_else(|_| "unknown".to_string()),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.state.start_time.elapsed().as_secs(),
            cpu_usage: 0.0, // TODO: implement
            memory_usage_mb: 0, // TODO: implement
            events_processed: self.state.events_processed.load(std::sync::atomic::Ordering::Relaxed),
            threats_detected: self.state.threats_detected.load(std::sync::atomic::Ordering::Relaxed),
            last_heartbeat: chrono::Utc::now(),
        }
    }
}
