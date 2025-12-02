use anyhow::Result;
use icenet_models::*;
use notify::{Watcher, RecursiveMode, Event as NotifyEvent, EventKind};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, debug, warn};
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;

use crate::config::Config;

pub struct FileMonitor {
    config: Arc<Config>,
    event_tx: mpsc::UnboundedSender<Event>,
}

impl FileMonitor {
    pub fn new(config: Arc<Config>, event_tx: mpsc::UnboundedSender<Event>) -> Result<Self> {
        Ok(Self { config, event_tx })
    }

    pub async fn run(self) -> Result<()> {
        info!("Starting file system monitor");

        let (tx, mut rx) = std::sync::mpsc::channel();

        // Create watcher
        let mut watcher = notify::recommended_watcher(tx)?;

        // Watch important directories
        let watch_paths = self.get_watch_paths();
        for path in &watch_paths {
            if Path::new(path).exists() {
                info!("Watching path: {}", path);
                watcher.watch(Path::new(path), RecursiveMode::Recursive)?;
            }
        }

        // Process events
        loop {
            match rx.recv() {
                Ok(Ok(notify_event)) => {
                    if let Err(e) = self.handle_file_event(notify_event).await {
                        warn!("Error handling file event: {}", e);
                    }
                }
                Ok(Err(e)) => warn!("File watcher error: {}", e),
                Err(e) => {
                    warn!("Channel receive error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_file_event(&self, notify_event: NotifyEvent) -> Result<()> {
        for path in notify_event.paths {
            let path_str = path.to_string_lossy().to_string();

            // Check if path should be excluded
            if self.is_excluded(&path_str) {
                continue;
            }

            let operation = match notify_event.kind {
                EventKind::Create(_) => FileOperation::Create,
                EventKind::Modify(_) => FileOperation::Modify,
                EventKind::Remove(_) => FileOperation::Delete,
                _ => continue,
            };

            // Get file metadata
            let metadata = fs::metadata(&path).ok();
            let size = metadata.as_ref().map(|m| m.len());
            let is_executable = self.is_executable(&path);

            // Calculate hash for new/modified files
            let hash_sha256 = if matches!(operation, FileOperation::Create | FileOperation::Modify) {
                self.calculate_hash(&path).ok()
            } else {
                None
            };

            let process_info = self.get_current_process_info();

            let file_event = FileEvent {
                path: path_str.clone(),
                operation,
                process_id: process_info.0,
                process_name: process_info.1,
                user: whoami::username(),
                hash_sha256,
                hash_md5: None,
                size,
                is_executable,
            };

            // Determine severity based on file type and location
            let severity = self.calculate_severity(&path_str, is_executable);

            let event = Event {
                event_id: uuid::Uuid::new_v4(),
                agent_id: self.config.agent.agent_id,
                timestamp: chrono::Utc::now(),
                event_type: EventType::FileCreated,
                severity,
                hostname: hostname::get()?.to_string_lossy().to_string(),
                os_type: if cfg!(windows) { OsType::Windows } else if cfg!(target_os = "macos") { OsType::MacOS } else { OsType::Linux },
                event_data: EventData::File(file_event),
                detection: None,
            };

            debug!("File event: {:?}", event);

            // Send event
            let _ = self.event_tx.send(event);
        }

        Ok(())
    }

    fn get_watch_paths(&self) -> Vec<String> {
        #[cfg(windows)]
        {
            vec![
                "C:\\Users".to_string(),
                "C:\\Windows\\System32".to_string(),
                "C:\\Program Files".to_string(),
                "C:\\Program Files (x86)".to_string(),
                "C:\\ProgramData".to_string(),
            ]
        }

        #[cfg(target_os = "macos")]
        {
            vec![
                "/Users".to_string(),
                "/Applications".to_string(),
                "/Library".to_string(),
                "/System".to_string(),
            ]
        }

        #[cfg(target_os = "linux")]
        {
            vec![
                "/home".to_string(),
                "/etc".to_string(),
                "/var".to_string(),
                "/usr/bin".to_string(),
                "/usr/local/bin".to_string(),
            ]
        }
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.config.agent.monitoring.excluded_paths
            .iter()
            .any(|excluded| path.starts_with(excluded))
    }

    fn is_executable(&self, path: &Path) -> bool {
        #[cfg(windows)]
        {
            path.extension()
                .and_then(|e| e.to_str())
                .map(|e| matches!(e.to_lowercase().as_str(), "exe" | "dll" | "sys" | "bat" | "ps1" | "vbs"))
                .unwrap_or(false)
        }

        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path)
                .ok()
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
    }

    fn calculate_hash(&self, path: &Path) -> Result<String> {
        let data = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }

    fn calculate_severity(&self, path: &str, is_executable: bool) -> Severity {
        // Higher severity for system directories and executables
        if is_executable {
            if path.contains("System32") || path.contains("/bin") || path.contains("/sbin") {
                return Severity::High;
            }
            return Severity::Medium;
        }

        Severity::Low
    }

    fn get_current_process_info(&self) -> (u32, String) {
        let pid = std::process::id();
        let name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        (pid, name)
    }
}
