#!/bin/bash
# KahLuna WARP Gateway -- Dynamic MOTD

HOSTNAME=$(hostname)
VERSION=$(cat /opt/warp-gateway/cli/__init__.py 2>/dev/null | grep __version__ | cut -d"'" -f2 || echo "0.1.0")
UPTIME=$(uptime -p 2>/dev/null | sed 's/up //' || echo "unknown")
WAN_IP=$(ip -4 addr show scope global 2>/dev/null | grep inet | head -1 | awk '{print $2}' | cut -d/ -f1 || echo "not configured")

echo ""
echo "  KahLuna WARP Gateway v${VERSION}"
echo "  Hostname: ${HOSTNAME}"
echo "  WAN IP:   ${WAN_IP}"
echo "  Uptime:   ${UPTIME}"
echo ""
echo "  Type 'help' for available commands."
echo ""
