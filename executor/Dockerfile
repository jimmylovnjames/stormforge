FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# System deps
RUN apt-get update && apt-get install -y \
    curl wget git nmap gobuster ffuf \
    python3 python3-pip dirb \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Go
RUN wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz && \
    rm go1.22.5.linux-amd64.tar.gz

# ProjectDiscovery tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# sqlmap
RUN pip3 install sqlmap

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

WORKDIR /app
COPY . .

CMD ["node", "executor.mjs"]
