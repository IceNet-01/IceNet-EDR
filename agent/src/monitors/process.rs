use anyhow::Result;
use icenet_models::*;
use sysinfo::{System, SystemExt, ProcessExt, PidExt};
use std::sync::Arc;
use std::collections::HashSet;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{info, debug, warn};

use crate::config::Config;

pub struct ProcessMonitor {
    config: Arc<Config>,
    event_tx: mpsc::UnboundedSender<Event>,
    known_processes: HashSet<u32>,
}

impl ProcessMonitor {
    pub fn new(config: Arc<Config>, event_tx: mpsc::UnboundedSender<Event>) -> Result<Self> {
        Ok(Self {
            config,
            event_tx,
            known_processes: HashSet::new(),
        })
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Starting process monitor");

        let mut sys = System::new_all();
        let mut check_interval = interval(Duration::from_secs(1));

        // Initialize known processes
        sys.refresh_processes();
        for (pid, _) in sys.processes() {
            self.known_processes.insert(pid.as_u32());
        }

        loop {
            check_interval.tick().await;

            sys.refresh_processes();
            let current_pids: HashSet<u32> = sys.processes()
                .keys()
                .map(|pid| pid.as_u32())
                .collect();

            // Detect new processes
            for pid in current_pids.difference(&self.known_processes) {
                if let Some(process) = sys.process(sysinfo::Pid::from_u32(*pid)) {
                    if let Err(e) = self.handle_process_created(*pid, process).await {
                        warn!("Error handling process creation: {}", e);
                    }
                }
            }

            // Detect terminated processes
            for pid in self.known_processes.difference(&current_pids) {
                if let Err(e) = self.handle_process_terminated(*pid).await {
                    warn!("Error handling process termination: {}", e);
                }
            }

            self.known_processes = current_pids;
        }
    }

    async fn handle_process_created(&self, pid: u32, process: &sysinfo::Process) -> Result<()> {
        let process_name = process.name().to_string();

        // Check if process should be excluded
        if self.is_excluded(&process_name) {
            return Ok(());
        }

        let parent_pid = process.parent()
            .map(|p| p.as_u32())
            .unwrap_or(0);

        let exe_path = process.exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let cmd_line = process.cmd()
            .join(" ");

        let user = process.user_id()
            .map(|uid| format!("{:?}", uid))
            .unwrap_or_else(|| whoami::username());

        // Calculate hash of executable
        let hash_sha256 = if let Some(exe) = process.exe() {
            self.calculate_hash(exe).ok()
        } else {
            None
        };

        let parent_name = if parent_pid != 0 {
            String::from("unknown")  // TODO: get actual parent name
        } else {
            String::from("none")
        };

        let process_event = ProcessEvent {
            process_id: pid,
            parent_process_id: parent_pid,
            process_name: process_name.clone(),
            command_line: cmd_line.clone(),
            executable_path: exe_path.clone(),
            user: user.clone(),
            hash_sha256,
            parent_name,
            operation: ProcessOperation::Create,
        };

        // Determine severity
        let severity = self.calculate_severity(&process_name, &cmd_line, &exe_path);

        let event = Event {
            event_id: uuid::Uuid::new_v4(),
            agent_id: self.config.agent.agent_id,
            timestamp: chrono::Utc::now(),
            event_type: EventType::ProcessCreated,
            severity,
            hostname: hostname::get()?.to_string_lossy().to_string(),
            os_type: if cfg!(windows) { OsType::Windows } else if cfg!(target_os = "macos") { OsType::MacOS } else { OsType::Linux },
            event_data: EventData::Process(process_event),
            detection: None,
        };

        debug!("Process created: {} (PID: {})", process_name, pid);

        // Send event
        let _ = self.event_tx.send(event);

        Ok(())
    }

    async fn handle_process_terminated(&self, pid: u32) -> Result<()> {
        debug!("Process terminated: PID {}", pid);

        let process_event = ProcessEvent {
            process_id: pid,
            parent_process_id: 0,
            process_name: "unknown".to_string(),
            command_line: String::new(),
            executable_path: String::new(),
            user: String::new(),
            hash_sha256: None,
            parent_name: String::new(),
            operation: ProcessOperation::Terminate,
        };

        let event = Event {
            event_id: uuid::Uuid::new_v4(),
            agent_id: self.config.agent.agent_id,
            timestamp: chrono::Utc::now(),
            event_type: EventType::ProcessTerminated,
            severity: Severity::Low,
            hostname: hostname::get()?.to_string_lossy().to_string(),
            os_type: if cfg!(windows) { OsType::Windows } else if cfg!(target_os = "macos") { OsType::MacOS } else { OsType::Linux },
            event_data: EventData::Process(process_event),
            detection: None,
        };

        let _ = self.event_tx.send(event);

        Ok(())
    }

    fn is_excluded(&self, process_name: &str) -> bool {
        self.config.agent.monitoring.excluded_processes
            .iter()
            .any(|excluded| process_name.contains(excluded))
    }

    fn calculate_hash(&self, path: &std::path::Path) -> Result<String> {
        use sha2::{Sha256, Digest};
        use std::fs;

        let data = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }

    fn calculate_severity(&self, process_name: &str, cmd_line: &str, exe_path: &str) -> Severity {
        let suspicious_patterns = [
            "powershell", "cmd.exe", "wscript", "cscript", "regsvr32",
            "rundll32", "mshta", "certutil", "bitsadmin", "wmic",
        ];

        let suspicious_args = [
            "-enc", "-encodedcommand", "downloadstring", "invoke-expression",
            "iex", "bypass", "hidden", "-w hidden",
        ];

        // Check for suspicious process names
        let name_lower = process_name.to_lowercase();
        if suspicious_patterns.iter().any(|p| name_lower.contains(p)) {
            // Check for suspicious command line arguments
            let cmd_lower = cmd_line.to_lowercase();
            if suspicious_args.iter().any(|a| cmd_lower.contains(a)) {
                return Severity::High;
            }
            return Severity::Medium;
        }

        // Check for execution from temp directories
        if exe_path.contains("Temp") || exe_path.contains("tmp") || exe_path.contains("AppData\\Local\\Temp") {
            return Severity::Medium;
        }

        Severity::Low
    }
}
