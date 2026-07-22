# StormForge Executor — Installation Guide

## Requirements

- Linux VPS (Ubuntu 22.04+ recommended) or Docker
- Node.js 18+
- Root/sudo access (for nmap)

## Quick Install (Ubuntu/Debian)

```bash
# System deps
sudo apt update && sudo apt install -y nmap gobuster ffuf curl git

# Go tools (subfinder, httpx, katana, nuclei)
# Install Go first if not present
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin:~/go/bin

# ProjectDiscovery tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update nuclei templates
nuclei -update-templates

# sqlmap (Python)
sudo apt install -y python3 python3-pip
pip3 install sqlmap

# Wordlists
sudo mkdir -p /usr/share/wordlists/dirb
sudo apt install -y dirb  # installs common.txt
# Or manually:
# wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
#   -O /usr/share/wordlists/dirb/common.txt
```

## Docker (Recommended)

```bash
docker build -t stormforge-executor .
docker run -d \
  -e STORMFORGE_C2_URL=https://stormforge.YOUR-SUBDOMAIN.workers.dev \
  -e EXECUTOR_SECRET=your-shared-secret \
  -e POLL_INTERVAL=5000 \
  -e MAX_CONCURRENT=3 \
  --name sf-executor \
  stormforge-executor
```

## Running

```bash
# Set environment
export STORMFORGE_C2_URL=https://stormforge.YOUR-SUBDOMAIN.workers.dev
export EXECUTOR_SECRET=your-shared-secret-here
export POLL_INTERVAL=5000
export MAX_CONCURRENT=3

# Run
node executor.mjs
```

Structured JSON logs include `exec_start` / `exec_done` / `exec_error` with the exact command and stdout/stderr previews. Optional: `C2_RETRIES` (default 3), `DEFAULT_TIMEOUT_SEC` (default 300). Local-only escape hatch: `ALLOW_INSECURE_EXECUTOR=true` (must also be set on the Worker).

## Verify Tools

```bash
node check-tools.mjs
```
