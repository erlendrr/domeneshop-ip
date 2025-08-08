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

# Check if auto-update config exists
CONFIG_DIR="$HOME/.config/domeneshop"
CONFIG_FILE="$CONFIG_DIR/auto_update_config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}Warning: Auto-update configuration not found at $CONFIG_FILE${NC}"
    echo "You need to run domeneshop-ip in interactive mode first and enable auto-update."
    echo ""
    echo "Run: $BINARY_PATH"
    echo "Then follow the prompts to set up auto-update."
    echo ""
    read -p "Do you want to continue with cron setup anyway? (y/N): " -n 1 -r
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
echo -e "${YELLOW}Setting up cron job...${NC}"

# Create the cron job entry
CRON_ENTRY="* * * * * $BINARY_PATH --check-and-update >/dev/null 2>&1"

# Check if entry already exists
if crontab -l 2>/dev/null | grep -q "domeneshop-ip --check-and-update"; then
    echo -e "${YELLOW}Cron job for domeneshop-ip already exists!${NC}"
    echo ""
    crontab -l | grep "domeneshop-ip"
    echo ""
    read -p "Do you want to replace it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi

    # Remove existing entries
    crontab -l 2>/dev/null | grep -v "domeneshop-ip --check-and-update" | crontab -
fi

# Add new cron job
(crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -

echo -e "${GREEN}✓ Cron job added successfully!${NC}"
echo ""
echo "The following cron job has been set up:"
echo "$CRON_ENTRY"
echo ""
echo "This will check for IP changes every minute and update DNS records only when needed."

# Offer to set up with logging
echo ""
read -p "Do you want to enable logging to see when updates occur? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    LOG_DIR="$HOME/.local/share/domeneshop"
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/auto_update.log"

    # Remove the silent cron job and add one with logging
    crontab -l | grep -v "domeneshop-ip --check-and-update" | crontab -

    CRON_ENTRY_WITH_LOG="* * * * * $BINARY_PATH --check-and-update >> $LOG_FILE 2>&1"
    (crontab -l 2>/dev/null; echo "$CRON_ENTRY_WITH_LOG") | crontab -

    echo -e "${GREEN}✓ Logging enabled!${NC}"
    echo "Logs will be written to: $LOG_FILE"
    echo "All log entries include timestamps for easy monitoring."
    echo ""
    echo "To view recent logs:"
    echo "tail -f $LOG_FILE"
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
