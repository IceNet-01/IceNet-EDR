use anyhow::Result;
use icenet_models::*;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{info, debug, warn};

use crate::config::Config;

pub struct NetworkMonitor {
    config: Arc<Config>,
    event_tx: mpsc::UnboundedSender<Event>,
}

impl NetworkMonitor {
    pub fn new(config: Arc<Config>, event_tx: mpsc::UnboundedSender<Event>) -> Result<Self> {
        Ok(Self { config, event_tx })
    }

    pub async fn run(self) -> Result<()> {
        info!("Starting network monitor");

        let mut check_interval = interval(Duration::from_secs(5));

        loop {
            check_interval.tick().await;

            if let Err(e) = self.check_connections().await {
                warn!("Error checking connections: {}", e);
            }
        }
    }

    async fn check_connections(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // On Linux, parse /proc/net/tcp and /proc/net/udp
            self.check_linux_connections().await?;
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, use Windows API
            self.check_windows_connections().await?;
        }

        #[cfg(target_os = "macos")]
        {
            // On macOS, use system commands or network framework
            self.check_macos_connections().await?;
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn check_linux_connections(&self) -> Result<()> {
        use std::fs;

        // Parse TCP connections
        if let Ok(tcp_data) = fs::read_to_string("/proc/net/tcp") {
            for line in tcp_data.lines().skip(1) {
                if let Some(conn) = self.parse_linux_connection(line, NetworkProtocol::TCP) {
                    self.send_network_event(conn).await?;
                }
            }
        }

        // Parse UDP connections
        if let Ok(udp_data) = fs::read_to_string("/proc/net/udp") {
            for line in udp_data.lines().skip(1) {
                if let Some(conn) = self.parse_linux_connection(line, NetworkProtocol::UDP) {
                    self.send_network_event(conn).await?;
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn parse_linux_connection(&self, line: &str, protocol: NetworkProtocol) -> Option<NetworkEvent> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        // Parse local address
        let local_parts: Vec<&str> = parts[1].split(':').collect();
        if local_parts.len() != 2 {
            return None;
        }

        let local_port = u16::from_str_radix(local_parts[1], 16).ok()?;
        let local_addr = self.parse_hex_ip(local_parts[0])?;

        // Parse remote address
        let remote_parts: Vec<&str> = parts[2].split(':').collect();
        if remote_parts.len() != 2 {
            return None;
        }

        let remote_port = u16::from_str_radix(remote_parts[1], 16).ok()?;
        let remote_addr = self.parse_hex_ip(remote_parts[0])?;

        // Get UID (user)
        let _uid = parts.get(7)?;

        Some(NetworkEvent {
            process_id: 0, // TODO: map inode to PID
            process_name: "unknown".to_string(),
            protocol,
            local_address: local_addr,
            local_port,
            remote_address: remote_addr,
            remote_port,
            direction: if remote_port == 0 {
                NetworkDirection::Outbound
            } else {
                NetworkDirection::Inbound
            },
            bytes_sent: 0,
            bytes_received: 0,
            dns_query: None,
        })
    }

    #[cfg(target_os = "linux")]
    fn parse_hex_ip(&self, hex: &str) -> Option<String> {
        if hex.len() != 8 {
            return None;
        }

        let ip_int = u32::from_str_radix(hex, 16).ok()?;
        let ip = format!(
            "{}.{}.{}.{}",
            ip_int & 0xFF,
            (ip_int >> 8) & 0xFF,
            (ip_int >> 16) & 0xFF,
            (ip_int >> 24) & 0xFF
        );

        Some(ip)
    }

    #[cfg(target_os = "windows")]
    async fn check_windows_connections(&self) -> Result<()> {
        // TODO: Implement Windows connection monitoring using Windows API
        // This would use GetTcpTable2 and GetUdpTable
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn check_macos_connections(&self) -> Result<()> {
        // TODO: Implement macOS connection monitoring
        Ok(())
    }

    async fn send_network_event(&self, network_event: NetworkEvent) -> Result<()> {
        // Determine severity based on destination
        let severity = self.calculate_severity(&network_event);

        // Skip local connections
        if self.is_local(&network_event.remote_address) {
            return Ok(());
        }

        let event = Event {
            event_id: uuid::Uuid::new_v4(),
            agent_id: self.config.agent.agent_id,
            timestamp: chrono::Utc::now(),
            event_type: EventType::NetworkConnection,
            severity,
            hostname: hostname::get()?.to_string_lossy().to_string(),
            os_type: if cfg!(windows) { OsType::Windows } else if cfg!(target_os = "macos") { OsType::MacOS } else { OsType::Linux },
            event_data: EventData::Network(network_event),
            detection: None,
        };

        debug!("Network connection event: {:?}", event);

        // Send event
        let _ = self.event_tx.send(event);

        Ok(())
    }

    fn is_local(&self, address: &str) -> bool {
        address.starts_with("127.") ||
        address.starts_with("0.0.0.0") ||
        address == "::1" ||
        address.starts_with("192.168.") ||
        address.starts_with("10.") ||
        address.starts_with("172.16.")
    }

    fn calculate_severity(&self, event: &NetworkEvent) -> Severity {
        // Check for suspicious ports
        let suspicious_ports = [
            4444, 4445, 5555, 6666, 7777, 8888, 9999, // Common backdoor ports
            31337, 12345, 54321, // Known trojan ports
        ];

        if suspicious_ports.contains(&event.remote_port) {
            return Severity::High;
        }

        // Check for known C2 infrastructure (placeholder - would use threat intel)
        // if self.is_known_c2(&event.remote_address) {
        //     return Severity::Critical;
        // }

        match event.protocol {
            NetworkProtocol::HTTP | NetworkProtocol::HTTPS => Severity::Low,
            NetworkProtocol::DNS => Severity::Info,
            _ => Severity::Medium,
        }
    }
}
