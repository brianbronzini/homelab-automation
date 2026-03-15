#!/bin/bash

set -euo pipefail

# Load secrets
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_FILE="$SCRIPT_DIR/../secrets.env"

if [ -f "$SECRETS_FILE" ]; then
    source "$SECRETS_FILE"
else
    echo "ERROR: secrets.env not found" >&2
    exit 1
fi

if [ -z "${DISCORD_WEBHOOK:-}" ]; then
    echo "ERROR: DISCORD_WEBHOOK not set in secrets.env" >&2
    exit 1
fi

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }

# Get Threat Intel metrics
log "Checking Threat Intel..."
TI_RAM=$(ssh threat-intel "sudo free -h | grep Mem | awk '{print \$3}'" 2>/dev/null) || TI_RAM="N/A"
TI_DISK=$(ssh threat-intel "df -h / | tail -1 | awk '{print \$5}'" 2>/dev/null) || TI_DISK="N/A"
TI_CACHE=$(ssh threat-intel "du -sh /home/threatintel/threat-intel-aggregator/data/cache.db 2>/dev/null | awk '{print \$1}'" 2>/dev/null) || TI_CACHE="N/A"

# Get Wazuh metrics
log "Checking Wazuh..."
WZ_RAM=$(ssh wazuh "sudo free -h | grep Mem | awk '{print \$3}'" 2>/dev/null) || WZ_RAM="N/A"
WZ_DISK=$(ssh wazuh "df -h / | tail -1 | awk '{print \$5}'" 2>/dev/null) || WZ_DISK="N/A"
WZ_LOGS=$(ssh wazuh "du -sh /var/ossec/logs 2>/dev/null | awk '{print \$1}'" 2>/dev/null) || WZ_LOGS="N/A"
WZ_INDEX=$(ssh wazuh "du -sh /var/lib/wazuh-indexer 2>/dev/null | awk '{print \$1}'" 2>/dev/null) || WZ_INDEX="N/A"
WZ_AGENTS=$(ssh wazuh "sudo /var/ossec/bin/agent_control -l 2>/dev/null | grep -c 'Active'" 2>/dev/null) || WZ_AGENTS="0"

# Get Proxmox Host metrics
log "Checking Proxmox Host..."
HOST_RAM=$(ssh proxmox "free -h | grep Mem | awk '{print \$3\"/\"\$2}'" 2>/dev/null) || HOST_RAM="N/A"
HOST_LOAD=$(ssh proxmox "uptime | awk -F'load average:' '{print \$2}' | cut -d',' -f1 | xargs" 2>/dev/null) || HOST_LOAD="N/A"
HOST_DISK=$(ssh proxmox "df -h / | tail -1 | awk '{print \$5}'" 2>/dev/null) || HOST_DISK="N/A"

# Get security activity
log "Checking activity..."
ENRICHMENTS=$(ssh wazuh "tail -1000 /var/ossec/logs/active-responses.log 2>/dev/null | grep -c 'Enriching'" 2>/dev/null) || ENRICHMENTS="0"
BLOCKED=$(ssh wazuh "tail -1000 /var/ossec/logs/active-responses.log 2>/dev/null | grep -c 'BLOCKING'" 2>/dev/null) || BLOCKED="0"

# Build description
DESCRIPTION="Threat Intel API
RAM: $TI_RAM
Disk: $TI_DISK
Cache: $TI_CACHE

Wazuh SIEM
RAM: $WZ_RAM
Disk: $WZ_DISK
Logs: $WZ_LOGS
Index: $WZ_INDEX
Agents: $WZ_AGENTS active

Proxmox Host
RAM: $HOST_RAM
Load: $HOST_LOAD
Disk: $HOST_DISK

Activity (24h)
Enrichments: $ENRICHMENTS
Blocked: $BLOCKED"

log "Sending to Discord..."

# Build payload with jq (guarantees valid JSON)
PAYLOAD=$(jq -n \
  --arg title "Security Stack Metrics" \
  --arg desc "$DESCRIPTION" \
  --argjson color 3066993 \
  --arg footer "homelab security • $(date '+%b %d at %H:%M')" \
  '{
    embeds: [{
      title: $title,
      description: $desc,
      color: $color,
      footer: {
        text: $footer
      }
    }]
  }')

# Send to Discord
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -H "Content-Type: application/json" -d "$PAYLOAD" "$DISCORD_WEBHOOK" 2>&1)

if echo "$RESPONSE" | grep -q "HTTP_CODE:2"; then
    log "Successfully sent to Discord"
else
    log "ERROR: Failed to send to Discord"
    echo "$RESPONSE" >&2
    exit 1
fi

log "Metrics report complete"
