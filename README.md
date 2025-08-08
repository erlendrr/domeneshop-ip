# Domeneshop IP Updater

A CLI tool for updating DNS records at Domeneshop with your current IP address.

## Installation

```
cargo install domeneshop-ip
```

## Usage

```
domeneshop-ip [OPTIONS]
```

### Options

```
--token <TOKEN>            Domeneshop API token [env: DOMENESHOP_API_TOKEN=]
--secret <SECRET>          Domeneshop API secret [env: DOMENESHOP_API_SECRET=]
--domain-input <DOMAIN>    Domain to manage (e.g. example.com or sub.example.com)
-y, --yes                  Skip all confirmation prompts
--check-and-update         Check and update DNS record if IP has changed (for cron jobs)
--help                     Show help information
--version                  Show version information
```

## Features

- Automatically detects your public IP address
- Lists available network interfaces
- Updates DNS A or AAAA records at Domeneshop
- Stores API credentials securely for future use
- Interactive mode with confirmation prompts
- **Auto-update mode**: Automatically update DNS records when your IP changes
- **Cron job support**: Run periodic checks without user interaction

## Auto-Update Setup

After successfully updating a DNS record, the tool will offer to set up automatic updates. If enabled:

1. Configuration is saved securely to `~/.config/domeneshop/auto_update_config.json`
2. The tool provides a cron job command to run every minute
3. Use `--check-and-update` flag to check for IP changes and update only when needed

### Example Cron Job

To check for IP changes every minute:

```bash
# Edit your cron jobs
crontab -e

# Add this line (replace path with your actual binary path):
* * * * * /path/to/domeneshop-ip --check-and-update
```

The auto-update process:
- Fetches your current public IP address
- Compares it with the current DNS record
- Updates the DNS record **only** if the IP has changed
- Logs results for monitoring

## License

Apache-2.0
