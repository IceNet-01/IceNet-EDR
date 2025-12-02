use serde::{Deserialize, Serialize};
use icenet_models::*;

/// Messages sent from agent to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    /// Agent registration and initial handshake
    Register {
        agent_id: AgentId,
        hostname: String,
        os_type: OsType,
        os_version: String,
        agent_version: String,
    },

    /// Periodic heartbeat with status
    Heartbeat(AgentStatus),

    /// Security event detected
    Event(Event),

    /// Batch of events (for efficiency)
    EventBatch(Vec<Event>),

    /// Response to a command from server
    CommandResponse {
        command_id: uuid::Uuid,
        success: bool,
        message: String,
        data: Option<serde_json::Value>,
    },

    /// Request for updated configuration
    ConfigRequest,
}

/// Messages sent from server to agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Registration acknowledgment
    RegisterAck {
        success: bool,
        message: String,
        config: Option<AgentConfig>,
    },

    /// Heartbeat acknowledgment
    HeartbeatAck,

    /// Command to execute an action
    Command {
        command_id: uuid::Uuid,
        action: ResponseAction,
    },

    /// Updated configuration
    ConfigUpdate(AgentConfig),

    /// Updated threat intelligence
    ThreatIntelligenceUpdate {
        indicators: Vec<ThreatIndicator>,
        yara_rules: Option<Vec<u8>>,
    },

    /// Request for forensic data
    ForensicsRequest {
        request_id: uuid::Uuid,
        artifacts: Vec<String>,
    },
}

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u32 = 1;

/// Message envelope with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope<T> {
    pub version: u32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub message_id: uuid::Uuid,
    pub payload: T,
}

impl<T> MessageEnvelope<T> {
    pub fn new(payload: T) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            timestamp: chrono::Utc::now(),
            message_id: uuid::Uuid::new_v4(),
            payload,
        }
    }
}

/// Serialize message to bytes
pub fn serialize_message<T: Serialize>(msg: &MessageEnvelope<T>) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(msg)
}

/// Deserialize message from bytes
pub fn deserialize_message<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<MessageEnvelope<T>, bincode::Error> {
    bincode::deserialize(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = MessageEnvelope::new(AgentMessage::ConfigRequest);
        let serialized = serialize_message(&msg).unwrap();
        let deserialized: MessageEnvelope<AgentMessage> = deserialize_message(&serialized).unwrap();

        assert_eq!(msg.version, deserialized.version);
        assert_eq!(msg.message_id, deserialized.message_id);
    }
}
