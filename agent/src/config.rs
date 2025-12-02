use anyhow::{Context, Result};
use icenet_models::AgentConfig;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
    pub max_size_mb: u32,
    pub max_backups: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: Some("/var/log/icenet-agent.log".to_string()),
            max_size_mb: 100,
            max_backups: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub verify_server: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            verify_server: true,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: AgentConfig::default(),
            logging: LoggingConfig::default(),
            tls: TlsConfig::default(),
        }
    }
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        // Support both YAML and JSON
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            serde_json::from_str(&content)
                .with_context(|| "Failed to parse JSON config")
        } else {
            serde_yaml::from_str(&content)
                .with_context(|| "Failed to parse YAML config")
        }
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content = if path.extension().and_then(|s| s.to_str()) == Some("json") {
            serde_json::to_string_pretty(self)?
        } else {
            serde_yaml::to_string(self)?
        };

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }
}
