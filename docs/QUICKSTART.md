# IceNet EDR - Quick Start Guide

This guide will help you quickly get IceNet EDR up and running.

## Prerequisites

### For Server
- Docker and Docker Compose (recommended)
- OR: PostgreSQL 15+, Redis 7+, NATS 2.10+, Go 1.21+

### For Agent
- Rust 1.75+ (for building from source)
- OR: Pre-built binaries for your platform

### Minimum System Requirements
- **Server**: 4GB RAM, 2 CPU cores, 20GB disk space
- **Agent**: 512MB RAM, minimal CPU impact (< 5% average)

## Server Installation (Docker - Recommended)

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/icenet-edr.git
cd icenet-edr
```

### Step 2: Configure Environment

Edit `docker-compose.yml` and change the default passwords:

```yaml
POSTGRES_PASSWORD: your_secure_password_here
```

### Step 3: Start the Server

```bash
docker-compose up -d
```

This will start:
- PostgreSQL database
- Redis cache
- NATS message broker
- IceNet server (API)
- Dashboard (web interface)

### Step 4: Verify Installation

Check that all services are running:

```bash
docker-compose ps
```

Access the dashboard at: http://localhost:3000

## Agent Installation

### Windows

#### From Pre-built Binary

1. Download the latest Windows agent from releases
2. Open PowerShell as Administrator
3. Install the agent as a service:

```powershell
.\icenet-agent.exe install
```

4. Configure the agent:

Edit `C:\Program Files\IceNet\config.yaml` and set your server URL:

```yaml
agent:
  server_url: "https://your-server:8443"
```

5. Start the service:

```powershell
Start-Service IceNetAgent
```

#### From Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build agent
cd agent
cargo build --release

# Install
target\release\icenet-agent.exe install
```

### Linux

#### From Pre-built Binary

1. Download the latest Linux agent from releases
2. Install as root:

```bash
sudo ./icenet-agent install
```

3. Configure the agent:

Edit `/etc/icenet/config.yaml`:

```yaml
agent:
  server_url: "https://your-server:8443"
```

4. Start the service:

```bash
sudo systemctl start icenet-agent
sudo systemctl enable icenet-agent
```

#### From Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build agent
cd agent
cargo build --release

# Install
sudo target/release/icenet-agent install
```

### macOS

#### From Pre-built Binary

1. Download the latest macOS agent from releases
2. Install as root:

```bash
sudo ./icenet-agent install
```

3. Configure the agent:

Edit `/etc/icenet/config.yaml`:

```yaml
agent:
  server_url: "https://your-server:8443"
```

4. Load the service:

```bash
sudo launchctl load ~/Library/LaunchAgents/com.icenet.agent.plist
```

## First Steps

### 1. Access the Dashboard

Navigate to http://localhost:3000 (or your server's address)

### 2. View Registered Agents

Go to the "Agents" tab to see all registered endpoints

### 3. Monitor Events

View real-time security events in the "Events" tab

### 4. Review Alerts

Check the "Alerts" tab for detected threats

### 5. Take Actions

Respond to threats using the action buttons:
- Quarantine files
- Terminate processes
- Block network connections
- Isolate hosts

## Configuration

### Agent Configuration

The agent can be configured via YAML file located at:
- Windows: `C:\Program Files\IceNet\config.yaml`
- Linux: `/etc/icenet/config.yaml`
- macOS: `/etc/icenet/config.yaml`

See `agent/config.example.yaml` for all available options.

### Server Configuration

Server configuration is done via environment variables in `docker-compose.yml`:

```yaml
environment:
  PORT: 8443
  DATABASE_URL: postgres://...
  NATS_URL: nats://...
  REDIS_URL: redis://...
```

## Testing

### Verify Agent is Working

1. Create a test file:

```bash
# Linux/macOS
echo "test" > /tmp/test.txt

# Windows
echo "test" > C:\temp\test.txt
```

2. Check the dashboard Events tab - you should see a file creation event

### Test Threat Detection

⚠️ **WARNING**: Only run this on test systems!

The agent detects suspicious patterns. You can test with:

```bash
# This will trigger behavioral detection (safe test)
echo "This is a test" > test.txt
```

Do NOT run actual malware for testing.

## Troubleshooting

### Agent Not Connecting

1. Check agent logs:
   - Windows: `C:\ProgramData\IceNet\logs\agent.log`
   - Linux: `/var/log/icenet-agent.log`
   - macOS: `/var/log/icenet-agent.log`

2. Verify server is reachable:
```bash
curl https://your-server:8443/health
```

3. Check firewall settings

### Server Not Starting

1. Check Docker logs:
```bash
docker-compose logs server
```

2. Verify database connection:
```bash
docker-compose logs postgres
```

### High CPU Usage

If the agent is using too much CPU:

1. Edit config and reduce monitoring scope:
```yaml
monitoring:
  excluded_paths:
    - "/path/to/exclude"
```

2. Adjust performance limits:
```yaml
performance:
  max_cpu_percent: 5
```

## Security Best Practices

1. **Use TLS**: Always enable TLS for agent-server communication
2. **Change Default Passwords**: Update all default passwords in production
3. **Restrict Access**: Use firewall rules to limit server access
4. **Regular Updates**: Keep agents and server updated
5. **Monitor Logs**: Regularly review logs for suspicious activity

## Next Steps

- Read the [Architecture Overview](../README.md#architecture-overview)
- Learn about [Detection Methods](./DETECTION.md)
- Configure [Custom Rules](./RULES.md)
- Set up [Integrations](./INTEGRATIONS.md)

## Getting Help

- GitHub Issues: https://github.com/yourusername/icenet-edr/issues
- Documentation: https://docs.icenet-edr.io
- Community: https://community.icenet-edr.io

## License

See LICENSE file for details.
