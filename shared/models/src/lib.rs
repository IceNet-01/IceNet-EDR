use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Unique identifier for an agent
pub type AgentId = Uuid;

/// Unique identifier for an event
pub type EventId = Uuid;

/// Severity levels for events and alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Types of events the agent can detect
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    FileCreated,
    FileModified,
    FileDeleted,
    FileRenamed,
    ProcessCreated,
    ProcessTerminated,
    ProcessInjection,
    NetworkConnection,
    NetworkDnsQuery,
    RegistryKeyCreated,
    RegistryKeyModified,
    RegistryKeyDeleted,
    MalwareDetected,
    SuspiciousBehavior,
    RansomwareActivity,
    PrivilegeEscalation,
    PersistenceMechanism,
    LateralMovement,
    DataExfiltration,
    MemoryInjection,
    RootkitDetected,
}

/// File system event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: String,
    pub operation: FileOperation,
    pub process_id: u32,
    pub process_name: String,
    pub user: String,
    pub hash_sha256: Option<String>,
    pub hash_md5: Option<String>,
    pub size: Option<u64>,
    pub is_executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOperation {
    Create,
    Modify,
    Delete,
    Rename { old_path: String },
    Execute,
}

/// Process event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub process_id: u32,
    pub parent_process_id: u32,
    pub process_name: String,
    pub command_line: String,
    pub executable_path: String,
    pub user: String,
    pub hash_sha256: Option<String>,
    pub parent_name: String,
    pub operation: ProcessOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessOperation {
    Create,
    Terminate,
    Injection { target_pid: u32 },
    MemoryModification,
    PrivilegeEscalation,
}

/// Network event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub process_id: u32,
    pub process_name: String,
    pub protocol: NetworkProtocol,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub direction: NetworkDirection,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub dns_query: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    DNS,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
}

/// Registry event data (Windows-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub operation: RegistryOperation,
    pub process_id: u32,
    pub process_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryOperation {
    KeyCreated,
    KeyDeleted,
    ValueSet,
    ValueDeleted,
}

/// Detection result from threat analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub detection_id: Uuid,
    pub detection_type: DetectionType,
    pub malware_family: Option<String>,
    pub confidence: f32,
    pub description: String,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionType {
    Signature,
    Behavioral,
    Heuristic,
    MachineLearning,
    YaraRule { rule_name: String },
    ThreatIntelligence,
}

/// Complete event with all metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_id: EventId,
    pub agent_id: AgentId,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub severity: Severity,
    pub hostname: String,
    pub os_type: OsType,
    pub event_data: EventData,
    pub detection: Option<Detection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventData {
    File(FileEvent),
    Process(ProcessEvent),
    Network(NetworkEvent),
    Registry(RegistryEvent),
    Custom(serde_json::Value),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsType {
    Windows,
    MacOS,
    Linux,
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id: AgentId,
    pub server_url: String,
    pub update_interval_secs: u64,
    pub monitoring: MonitoringConfig,
    pub detection: DetectionConfig,
    pub response: ResponseConfig,
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub file_system: bool,
    pub processes: bool,
    pub network: bool,
    pub registry: bool,
    pub memory: bool,
    pub excluded_paths: Vec<String>,
    pub excluded_processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub real_time_scan: bool,
    pub behavioral_analysis: bool,
    pub ml_detection: bool,
    pub yara_rules: bool,
    pub signature_db: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub auto_quarantine: bool,
    pub allow_process_termination: bool,
    pub allow_network_blocking: bool,
    pub require_admin_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub max_cpu_percent: u8,
    pub max_memory_mb: u32,
    pub event_buffer_size: usize,
    pub scan_queue_size: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: Uuid::new_v4(),
            server_url: "https://localhost:8443".to_string(),
            update_interval_secs: 300,
            monitoring: MonitoringConfig {
                file_system: true,
                processes: true,
                network: true,
                registry: cfg!(windows),
                memory: true,
                excluded_paths: vec![],
                excluded_processes: vec![],
            },
            detection: DetectionConfig {
                real_time_scan: true,
                behavioral_analysis: true,
                ml_detection: true,
                yara_rules: true,
                signature_db: true,
            },
            response: ResponseConfig {
                auto_quarantine: true,
                allow_process_termination: true,
                allow_network_blocking: true,
                require_admin_approval: false,
            },
            performance: PerformanceConfig {
                max_cpu_percent: 10,
                max_memory_mb: 256,
                event_buffer_size: 10000,
                scan_queue_size: 100,
            },
        }
    }
}

/// Agent status and health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub agent_id: AgentId,
    pub hostname: String,
    pub os_type: OsType,
    pub os_version: String,
    pub agent_version: String,
    pub uptime_secs: u64,
    pub cpu_usage: f32,
    pub memory_usage_mb: u32,
    pub events_processed: u64,
    pub threats_detected: u64,
    pub last_heartbeat: DateTime<Utc>,
}

/// Response action to be taken
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub action_id: Uuid,
    pub agent_id: AgentId,
    pub action_type: ActionType,
    pub reason: String,
    pub auto_approved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    QuarantineFile { path: String },
    TerminateProcess { pid: u32 },
    BlockNetwork { address: String, port: u16 },
    IsolateHost,
    CollectForensics { artifacts: Vec<String> },
    UpdateConfiguration(AgentConfig),
}

/// Threat intelligence indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub malware_family: Option<String>,
    pub confidence: f32,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorType {
    FileHash,
    IpAddress,
    Domain,
    Url,
    Email,
    Registry,
    Mutex,
}
