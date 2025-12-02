use anyhow::Result;
use icenet_models::*;
use std::sync::Arc;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn, error};

use crate::config::Config;

pub struct ResponseHandler {
    config: Arc<Config>,
    quarantine_dir: PathBuf,
}

impl ResponseHandler {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        let quarantine_dir = if cfg!(windows) {
            PathBuf::from("C:\\ProgramData\\IceNet\\Quarantine")
        } else {
            PathBuf::from("/var/lib/icenet/quarantine")
        };

        // Create quarantine directory if it doesn't exist
        if !quarantine_dir.exists() {
            fs::create_dir_all(&quarantine_dir)?;
        }

        Ok(Self {
            config,
            quarantine_dir,
        })
    }

    pub async fn handle_threat(&self, event: &Event) -> Result<()> {
        let detection = match &event.detection {
            Some(d) => d,
            None => return Ok(()),
        };

        info!("Handling threat: {} (confidence: {})", detection.description, detection.confidence);

        // Take appropriate action based on event type and configuration
        match &event.event_data {
            EventData::File(file_event) => {
                if self.config.agent.response.auto_quarantine {
                    self.quarantine_file(&file_event.path, &detection.description).await?;
                }
            }
            EventData::Process(proc_event) => {
                if self.config.agent.response.allow_process_termination {
                    self.terminate_process(proc_event.process_id, &detection.description).await?;
                }
            }
            EventData::Network(net_event) => {
                if self.config.agent.response.allow_network_blocking {
                    self.block_connection(&net_event.remote_address, net_event.remote_port).await?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    async fn quarantine_file(&self, file_path: &str, reason: &str) -> Result<()> {
        info!("Quarantining file: {} - Reason: {}", file_path, reason);

        let source = Path::new(file_path);
        if !source.exists() {
            warn!("File not found for quarantine: {}", file_path);
            return Ok(());
        }

        // Generate quarantine filename with timestamp
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let filename = source.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let quarantine_path = self.quarantine_dir.join(format!("{}_{}", timestamp, filename));

        // Move file to quarantine
        match fs::rename(source, &quarantine_path) {
            Ok(_) => {
                info!("File quarantined successfully: {}", quarantine_path.display());

                // Save metadata about quarantined file
                self.save_quarantine_metadata(
                    file_path,
                    quarantine_path.to_str().unwrap(),
                    reason,
                )?;
            }
            Err(e) => {
                error!("Failed to quarantine file: {}", e);

                // If move fails, try to delete the file as last resort
                if let Err(del_err) = fs::remove_file(source) {
                    error!("Failed to delete malicious file: {}", del_err);
                } else {
                    warn!("Deleted malicious file instead of quarantining: {}", file_path);
                }
            }
        }

        Ok(())
    }

    async fn terminate_process(&self, pid: u32, reason: &str) -> Result<()> {
        info!("Terminating process: PID {} - Reason: {}", pid, reason);

        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::Threading::*;
            use windows::Win32::Foundation::*;

            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
                TerminateProcess(handle, 1)?;
                CloseHandle(handle)?;
            }

            info!("Process terminated successfully: PID {}", pid);
        }

        #[cfg(not(target_os = "windows"))]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            match kill(Pid::from_raw(pid as i32), Signal::SIGKILL) {
                Ok(_) => info!("Process terminated successfully: PID {}", pid),
                Err(e) => error!("Failed to terminate process {}: {}", pid, e),
            }
        }

        Ok(())
    }

    async fn block_connection(&self, address: &str, port: u16) -> Result<()> {
        info!("Blocking network connection: {}:{}", address, port);

        #[cfg(target_os = "windows")]
        {
            // Use Windows Firewall API or netsh command
            let output = std::process::Command::new("netsh")
                .args(&[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name=IceNet_Block_{}_{}", address, port),
                    "dir=out",
                    "action=block",
                    &format!("remoteip={}", address),
                    &format!("remoteport={}", port),
                ])
                .output()?;

            if output.status.success() {
                info!("Firewall rule added successfully");
            } else {
                error!("Failed to add firewall rule: {}", String::from_utf8_lossy(&output.stderr));
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Use iptables
            let output = std::process::Command::new("iptables")
                .args(&[
                    "-A",
                    "OUTPUT",
                    "-d",
                    address,
                    "-p",
                    "tcp",
                    "--dport",
                    &port.to_string(),
                    "-j",
                    "DROP",
                ])
                .output()?;

            if output.status.success() {
                info!("iptables rule added successfully");
            } else {
                error!("Failed to add iptables rule: {}", String::from_utf8_lossy(&output.stderr));
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Use pfctl on macOS
            warn!("Network blocking not yet implemented for macOS");
        }

        Ok(())
    }

    fn save_quarantine_metadata(&self, original_path: &str, quarantine_path: &str, reason: &str) -> Result<()> {
        let metadata = serde_json::json!({
            "original_path": original_path,
            "quarantine_path": quarantine_path,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "reason": reason,
        });

        let metadata_path = self.quarantine_dir.join("metadata.jsonl");
        let metadata_str = serde_json::to_string(&metadata)? + "\n";

        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(metadata_path)?;

        file.write_all(metadata_str.as_bytes())?;

        Ok(())
    }
}
