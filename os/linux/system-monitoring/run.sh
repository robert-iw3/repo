#!/usr/bin/env bash
set -euo pipefail

# Support both Podman and Docker seamlessly
CONTAINER_CLI="docker"
if command -v podman &> /dev/null; then
    CONTAINER_CLI="podman"
fi

echo "Building Linux Sentinel v0.2.0 (Alpha) using $CONTAINER_CLI..."
$CONTAINER_CLI build -t linux-sentinel:latest .

# Ensure host directories exist for mounting
mkdir -p /var/log/linux-sentinel/Behavior/Categories
mkdir -p /var/log/linux-sentinel/diagnostics

echo "Deploying sensor..."
$CONTAINER_CLI run -d \
    --name linux-sentinel-agent \
    --cap-add NET_ADMIN \
    --cap-add DAC_READ_SEARCH \
    --cap-add SYS_PTRACE \
    --cap-add SYS_ADMIN \
    --cap-add SYS_RESOURCE \
    --cap-add BPF \
    --cap-add PERFMON \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    -v $(pwd)/master.toml:/opt/linux-sentinel/master.toml:ro \
    -v /var/log/linux-sentinel:/var/log/linux-sentinel \
    --network host \
    --restart unless-stopped \
    linux-sentinel:latest