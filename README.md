# IceNet EDR

A comprehensive, cross-platform Endpoint Detection and Response (EDR) platform with advanced antivirus, threat protection, and intrusion detection capabilities.

## Architecture Overview

IceNet EDR follows a distributed agent-server architecture designed for enterprise-scale deployment with a focus on security, performance, and minimal system impact.

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Management Console                       │
│                    (Web Dashboard - React)                   │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS/WSS
┌──────────────────────────┴──────────────────────────────────┐
│                   Central Management Server                  │
│  ┌────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  API Gateway│  │Event Processor│  │Threat Intelligence │  │
│  └────────────┘  └──────────────┘  └────────────────────┘  │
│  ┌────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  Database  │  │ Rule Engine  │  │  ML Service        │  │
│  └────────────┘  └──────────────┘  └────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ TLS
         ┌─────────────────┼─────────────────┐
         │                 │                 │
┌────────┴────────┐ ┌──────┴──────┐ ┌───────┴────────┐
│  Windows Agent  │ │  macOS Agent│ │  Linux Agent   │
└─────────────────┘ └─────────────┘ └────────────────┘
```

### Agent Architecture (Per Endpoint)

```
┌─────────────────────────────────────────────────────────────┐
│                     EDR Agent (Rust)                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │            Communication Module                      │   │
│  │  - Secure TLS channel to server                     │   │
│  │  - Event buffering & compression                    │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────┐   │
│  │ File Monitor  │  │Process Monitor│ │Network Monitor │   │
│  │ - Real-time   │  │ - Creation    │  │ - Connections │   │
│  │   scanning    │  │ - Injection   │  │ - DNS queries │   │
│  │ - Hash calc   │  │ - Termination │  │ - Traffic     │   │
│  └───────────────┘  └──────────────┘  └────────────────┘   │
│                                                              │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────┐   │
│  │Registry Monitor│ │Memory Scanner│  │Behavior Engine │   │
│  │ (Windows)     │  │ - Rootkits   │  │ - Heuristics   │   │
│  │               │  │ - Shellcode  │  │ - Anomalies    │   │
│  └───────────────┘  └──────────────┘  └────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Local Detection Engine                       │   │
│  │  - YARA rules                                       │   │
│  │  - Signature matching                               │   │
│  │  - Behavioral analysis                              │   │
│  │  - ML-based detection (local inference)            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Response Module                              │   │
│  │  - Quarantine                                       │   │
│  │  - Process termination                              │   │
│  │  - Network blocking                                 │   │
│  │  - Forensic collection                              │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌────────────────┐  ┌─────────────────┐
│ Kernel Driver   │  │ System Hooks   │  │   Firewall      │
│ (Windows WFP)   │  │ (Platform API) │  │  Integration    │
└─────────────────┘  └────────────────┘  └─────────────────┘
```

## Key Features

### 🛡️ Threat Protection
- **Real-time File Scanning**: Monitor all file operations with minimal performance impact
- **Behavior-based Detection**: Identify threats by analyzing process behavior patterns
- **Signature-based Detection**: Extensive malware signature database with automatic updates
- **Memory Scanning**: Detect fileless malware and rootkits in memory
- **Exploit Prevention**: ASLR, DEP, and other exploit mitigation techniques

### 📊 Monitoring Capabilities
- **File System Monitoring**: Track all file create/modify/delete operations
- **Process Monitoring**: Monitor process creation, injection, and suspicious activity
- **Network Monitoring**: Track all network connections, DNS queries, and traffic patterns
- **Registry Monitoring** (Windows): Detect persistence mechanisms and suspicious registry changes
- **Kernel-level Monitoring**: Deep visibility into system operations

### 🔍 Detection Engines
- **YARA Integration**: Custom and community YARA rules for threat detection
- **Behavioral Analysis**: Detect ransomware, trojans, and APTs by behavior
- **Machine Learning**: Advanced ML models for zero-day threat detection
- **Threat Intelligence**: Integration with threat feeds and IOC databases
- **Heuristic Analysis**: Identify suspicious patterns without known signatures

### 🚨 Intrusion Detection System (IDS)
- **Network Intrusion Detection**: Monitor network traffic for attack patterns
- **Host-based IDS**: Detect unauthorized access and privilege escalation
- **Anomaly Detection**: Baseline normal behavior and flag deviations
- **Attack Pattern Recognition**: Identify MITRE ATT&CK techniques

### ⚡ Response & Remediation
- **Automated Quarantine**: Isolate threats immediately
- **Process Termination**: Kill malicious processes safely
- **Network Isolation**: Block C2 communications and lateral movement
- **File Restoration**: Restore files damaged by ransomware (with Volume Shadow Copy)
- **Forensic Collection**: Capture evidence for investigation

### 🎯 Design Principles
- **Security First**: All components run with least privilege, encrypted communications
- **Low Performance Impact**: Optimized for minimal CPU and memory footprint
- **Balanced Protection**: Strong security without annoying false positives
- **User-Friendly**: Silent operation, clear alerts only when necessary
- **Enterprise Ready**: Scalable architecture for thousands of endpoints

## Technology Stack

### Agent
- **Primary Language**: Rust (memory safety, performance, cross-platform)
- **Windows Kernel Driver**: C/C++ with WDK (Windows Driver Kit)
- **macOS System Extension**: Swift/C with Endpoint Security framework
- **Linux Kernel Module**: C with eBPF for monitoring

### Server
- **Backend**: Go (scalability, concurrency, easy deployment)
- **Database**: PostgreSQL (events, alerts, configuration)
- **Time-Series DB**: TimescaleDB or InfluxDB (metrics)
- **Message Queue**: NATS or RabbitMQ (event streaming)
- **Cache**: Redis (performance optimization)

### Dashboard
- **Frontend**: React + TypeScript
- **UI Framework**: Material-UI or Ant Design
- **Charts**: Recharts or Chart.js
- **Real-time**: WebSockets for live updates

### Detection
- **YARA**: Rule-based detection
- **ClamAV**: Open-source antivirus integration
- **ML Models**: TensorFlow Lite or ONNX for edge inference

## Project Structure

```
icenet-edr/
├── agent/                      # EDR Agent (Rust)
│   ├── core/                   # Core agent logic
│   ├── monitors/               # Monitoring modules
│   │   ├── file/
│   │   ├── process/
│   │   ├── network/
│   │   └── registry/
│   ├── detection/              # Detection engines
│   │   ├── yara/
│   │   ├── signatures/
│   │   └── behavioral/
│   ├── response/               # Response actions
│   └── platform/               # Platform-specific code
│       ├── windows/
│       ├── macos/
│       └── linux/
├── driver/                     # Kernel-mode drivers
│   ├── windows/                # Windows minifilter driver
│   ├── macos/                  # macOS system extension
│   └── linux/                  # Linux kernel module (eBPF)
├── server/                     # Management Server (Go)
│   ├── api/                    # REST API
│   ├── processor/              # Event processing
│   ├── rules/                  # Rule engine
│   ├── ml/                     # ML inference service
│   └── database/               # Database models
├── dashboard/                  # Web Dashboard (React)
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   └── services/
│   └── public/
├── shared/                     # Shared libraries
│   ├── protocol/               # Communication protocol
│   └── models/                 # Data models
├── rules/                      # Detection rules
│   ├── yara/
│   └── behavioral/
├── ml-models/                  # Machine learning models
├── tests/                      # Integration tests
├── docs/                       # Documentation
└── scripts/                    # Build and deployment scripts
```

## Development Phases

### Phase 1: Foundation (Windows Core)
- [x] Project structure and build system
- [ ] Windows agent core framework
- [ ] Basic file system monitoring
- [ ] Process monitoring
- [ ] Network monitoring
- [ ] Communication with server
- [ ] Basic management server
- [ ] Simple web dashboard

### Phase 2: Detection & Response
- [ ] YARA integration
- [ ] Signature database
- [ ] Behavioral analysis engine
- [ ] Quarantine system
- [ ] Automated response actions
- [ ] Alert management

### Phase 3: Advanced Features
- [ ] Memory scanning
- [ ] Rootkit detection
- [ ] ML-based detection
- [ ] IDS capabilities
- [ ] Threat intelligence integration
- [ ] Forensics tools

### Phase 4: Cross-Platform
- [ ] macOS agent port
- [ ] Linux agent port
- [ ] Cross-platform testing
- [ ] Platform-specific optimizations

### Phase 5: Enterprise Features
- [ ] Multi-tenancy
- [ ] Role-based access control
- [ ] Advanced reporting
- [ ] Compliance modules
- [ ] API for integrations

## Building from Source

### Prerequisites
- **Rust**: 1.75+ (rustup recommended)
- **Go**: 1.21+
- **Node.js**: 18+ (for dashboard)
- **Windows SDK** (for Windows driver development)
- **WDK** (Windows Driver Kit)
- **Docker** (for server deployment)

### Build Agent
```bash
cd agent
cargo build --release
```

### Build Server
```bash
cd server
go build -o icenet-server
```

### Build Dashboard
```bash
cd dashboard
npm install
npm run build
```

## Installation

### Agent Installation
```bash
# Windows (requires admin)
icenet-agent.exe install

# macOS (requires root)
sudo ./icenet-agent install

# Linux (requires root)
sudo ./icenet-agent install
```

### Server Installation
```bash
# Using Docker
docker-compose up -d

# Or manual installation
./icenet-server --config server.yaml
```

## Configuration

### Agent Configuration
```yaml
server:
  url: https://edr-server.example.com
  tls_cert: /etc/icenet/server.crt

monitoring:
  file_system: true
  processes: true
  network: true
  registry: true  # Windows only

detection:
  real_time_scan: true
  behavioral_analysis: true
  ml_detection: true

performance:
  max_cpu_usage: 10  # percentage
  max_memory_mb: 256

response:
  auto_quarantine: true
  allow_process_termination: true
  require_admin_approval: false
```

## Security Considerations

- **Code Signing**: All binaries are signed with trusted certificates
- **Encrypted Communication**: TLS 1.3 for all agent-server communication
- **Least Privilege**: Components run with minimal required privileges
- **Input Validation**: All inputs are validated and sanitized
- **Secure Storage**: Sensitive data encrypted at rest
- **Audit Logging**: All security-relevant actions are logged
- **Update Security**: Signed updates with rollback capability

## Performance Targets

- **CPU Usage**: < 5% average, < 15% peak
- **Memory Usage**: < 200MB typical
- **File Scan**: < 1ms for average file
- **Event Latency**: < 100ms from event to server
- **False Positive Rate**: < 0.1% for enterprise environments

## License

[To be determined]

## Contributing

[Contribution guidelines to be added]

## Support

[Support information to be added]
