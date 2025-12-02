use anyhow::{Context, Result};
use icenet_models::*;
use icenet_protocol::*;
use reqwest::Client;
use std::sync::Arc;
use tracing::{info, debug, error};

use crate::config::Config;

pub struct ServerConnection {
    config: Arc<Config>,
    client: Client,
}

impl ServerConnection {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self { config, client })
    }

    pub async fn register(
        &self,
        agent_id: AgentId,
        hostname: String,
        os_type: OsType,
    ) -> Result<()> {
        let os_version = sys_info::os_release()
            .unwrap_or_else(|_| "unknown".to_string());
        let agent_version = env!("CARGO_PKG_VERSION").to_string();

        let message = AgentMessage::Register {
            agent_id,
            hostname,
            os_type,
            os_version,
            agent_version,
        };

        let envelope = MessageEnvelope::new(message);
        let url = format!("{}/api/v1/agent/register", self.config.agent.server_url);

        debug!("Registering with server: {}", url);

        let response = self.client
            .post(&url)
            .json(&envelope)
            .send()
            .await
            .context("Failed to send registration request")?;

        if response.status().is_success() {
            info!("Successfully registered with server");
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Registration failed: {} - {}", status, body);
            anyhow::bail!("Registration failed: {}", status)
        }
    }

    pub async fn send_heartbeat(&self, status: AgentStatus) -> Result<()> {
        let message = AgentMessage::Heartbeat(status);
        let envelope = MessageEnvelope::new(message);
        let url = format!("{}/api/v1/agent/heartbeat", self.config.agent.server_url);

        let response = self.client
            .post(&url)
            .json(&envelope)
            .send()
            .await
            .context("Failed to send heartbeat")?;

        if !response.status().is_success() {
            let status = response.status();
            error!("Heartbeat failed: {}", status);
            anyhow::bail!("Heartbeat failed: {}", status);
        }

        Ok(())
    }

    pub async fn send_events(&self, events: Vec<Event>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let message = AgentMessage::EventBatch(events);
        let envelope = MessageEnvelope::new(message);
        let url = format!("{}/api/v1/agent/events", self.config.agent.server_url);

        debug!("Sending {} events to server", envelope.payload.clone().into_iter().count());

        let response = self.client
            .post(&url)
            .json(&envelope)
            .send()
            .await
            .context("Failed to send events")?;

        if !response.status().is_success() {
            let status = response.status();
            error!("Failed to send events: {}", status);
            anyhow::bail!("Failed to send events: {}", status);
        }

        Ok(())
    }
}
