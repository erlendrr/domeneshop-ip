#!/bin/bash

# Domeneshop IP Auto-Update Cron Setup Script
# This script helps set up automatic DNS record updates

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Domeneshop IP Auto-Update Cron Setup${NC}"
echo "======================================"

# Check if domeneshop-ip binary exists
BINARY_PATH=""
if command -v domeneshop-ip >/dev/null 2>&1; then
    BINARY_PATH=$(which domeneshop-ip)
elif [ -f "./target/release/domeneshop-ip" ]; then
    BINARY_PATH="$(pwd)/target/release/domeneshop-ip"
elif [ -f "./target/debug/domeneshop-ip" ]; then
    BINARY_PATH="$(pwd)/target/debug/domeneshop-ip"
else
    echo -e "${RED}Error: domeneshop-ip binary not found!${NC}"
    echo "Please either:"
    echo "1. Install with 'cargo install domeneshop-ip'"
    echo "2. Build with 'cargo build --release'"
    echo "3. Run this script from the project directory after building"
    exit 1
fi

echo -e "Found domeneshop-ip at: ${GREEN}$BINARY_PATH${NC}"

# Locate auto-update configs (supports multiple)
CONFIG_DIR="$HOME/.config/domeneshop"
AUTO_DIR="$CONFIG_DIR/auto_update"
LEGACY_FILE="$CONFIG_DIR/auto_update_config.json"

declare -a CONFIG_FILES=()

if [ -d "$AUTO_DIR" ]; then
    while IFS= read -r -d '' file; do
        CONFIG_FILES+=("$file")
    done < <(find "$AUTO_DIR" -type f -name "*.json" -print0 2>/dev/null)
fi

# Fallback to legacy single-config
if [ -f "$LEGACY_FILE" ]; then
    CONFIG_FILES+=("$LEGACY_FILE")
fi

if [ ${#CONFIG_FILES[@]} -eq 0 ]; then
    echo -e "${YELLOW}Warning: No auto-update configs found.${NC}"
    echo "Run $BINARY_PATH, update a DNS record, and enable auto-update for each host you want."
    read -p "Continue to set up a generic --all cron entry anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
fi

# Show current cron jobs
echo ""
echo "Current cron jobs for $(whoami):"
echo "================================"
crontab -l 2>/dev/null || echo "(No cron jobs currently set up)"

echo ""
echo -e "${YELLOW}Setting up cron job(s)...${NC}"

# Decide mode: per-config entries (default) or single --all entry
MODE="per-config"
if [ ${#CONFIG_FILES[@]} -gt 1 ]; then
    read -p "Create separate entries per config (recommended) or one --all entry? [P/a]: " -n 1 -r choice
    echo
    if [[ $choice =~ ^[Aa]$ ]]; then
        MODE="all"
    fi
fi

if [ "$MODE" = "all" ]; then
    CRON_ENTRY="* * * * * $BINARY_PATH --check-and-update --all >/dev/null 2>&1"
    if crontab -l 2>/dev/null | grep -q "domeneshop-ip --check-and-update --all"; then
        echo -e "${YELLOW}An --all cron job already exists; skipping add.${NC}"
    else
        (crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -
        echo -e "${GREEN}✓ Added --all cron job${NC}"
        echo "$CRON_ENTRY"
    fi
else
    # Add/ensure an entry for each config
    for cfg in "${CONFIG_FILES[@]}"; do
        CRON_ENTRY="* * * * * $BINARY_PATH --check-and-update --config '$cfg' >/dev/null 2>&1"
        if crontab -l 2>/dev/null | grep -Fq "--check-and-update --config '$cfg'"; then
            echo -e "${YELLOW}Entry for $cfg already exists; skipping.${NC}"
        else
            (crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -
            echo -e "${GREEN}✓ Added cron for $cfg${NC}"
        fi
    done
fi

echo ""
echo "This will check for IP changes every minute and update DNS records only when needed."

# Offer to set up with logging
echo ""
read -p "Do you want to enable logging to see when updates occur? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    LOG_DIR="$HOME/.local/share/domeneshop"
    mkdir -p "$LOG_DIR"
    if [ "$MODE" = "all" ]; then
        LOG_FILE="$LOG_DIR/auto_update_all.log"
        # Remove existing --all silent entry and add logging variant
        crontab -l | grep -v "domeneshop-ip --check-and-update --all" | crontab -
        CRON_ENTRY_WITH_LOG="* * * * * $BINARY_PATH --check-and-update --all >> $LOG_FILE 2>&1"
        (crontab -l 2>/dev/null; echo "$CRON_ENTRY_WITH_LOG") | crontab -
        echo -e "${GREEN}✓ Logging enabled for --all!${NC}"
        echo "Logs: $LOG_FILE"
    else
        # Per-config logging files
        for cfg in "${CONFIG_FILES[@]}"; do
            base=$(basename "$cfg")
            LOG_FILE="$LOG_DIR/auto_update_${base%.json}.log"
            # Remove existing silent entry for this config and add logging variant
            crontab -l | grep -v "--check-and-update --config '$cfg'" | crontab -
            CRON_ENTRY_WITH_LOG="* * * * * $BINARY_PATH --check-and-update --config '$cfg' >> $LOG_FILE 2>&1"
            (crontab -l 2>/dev/null; echo "$CRON_ENTRY_WITH_LOG") | crontab -
            echo -e "${GREEN}✓ Logging enabled for $cfg${NC}"
            echo "Logs: $LOG_FILE"
        done
    fi
    echo "All log entries include timestamps for easy monitoring."
    echo ""
    echo "To view recent logs (example):"
    echo "tail -f $HOME/.local/share/domeneshop/auto_update_all.log"
fi

echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "Useful commands:"
echo "• View cron jobs:     crontab -l"
echo "• Edit cron jobs:     crontab -e"
echo "• Remove cron jobs:   crontab -r"
echo "• Test auto-update:   $BINARY_PATH --check-and-update"
echo ""
echo -e "${YELLOW}Note: The first check will run within the next minute.${NC}"
