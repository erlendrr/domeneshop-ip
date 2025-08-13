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
--config <PATH|NAME>       Path or name of an auto-update config to use with --check-and-update
--all                      Run --check-and-update for all saved configs
--help                     Show help information
--version                  Show version information
```

## Features

-   Automatically detects your public IP address
-   Lists available network interfaces
-   Updates DNS A or AAAA records at Domeneshop
-   Stores API credentials securely for future use
-   Interactive mode with confirmation prompts
-   **Auto-update mode**: Automatically update DNS records when your IP changes
-   **Cron job support**: Run periodic checks without user interaction
-   **Multi-domain/host**: Save multiple auto-update profiles and update each separately or all at once

## Auto-Update Setup

After successfully updating a DNS record, the tool will offer to set up automatic updates. If enabled:

1. A configuration is saved securely per host under `~/.config/domeneshop/auto_update/`
    - Example: `~/.config/domeneshop/auto_update/app.example.com__A.json`
2. The tool can add a cron job entry per config automatically
3. Use `--check-and-update` with `--config <file>` to check/update one host, or `--all` to handle all configs

### Example Cron Jobs

To check for IP changes every minute:

```bash
# Edit your cron jobs
crontab -e

# Update one specific host (recommended: one entry per host)
* * * * * /path/to/domeneshop-ip --check-and-update --config '/Users/you/.config/domeneshop/auto_update/app.example.com__A.json'

# Or update all saved hosts in one go
* * * * * /path/to/domeneshop-ip --check-and-update --all
```

The auto-update process:

-   Fetches your current public IP address
-   Compares it with the current DNS record
-   Updates the DNS record **only** if the IP has changed
-   Logs results for monitoring

## Typical multi-host setup

Repeat the interactive flow for each host you want to manage, e.g.:

-   app.bedrockchain.com
-   api.bedrockchain.com
-   www.bedrockchain.com

Enable auto-update when prompted each time. This creates separate config files under `~/.config/domeneshop/auto_update/` and the tool can create matching cron entries per host. You can also switch to a single `--all` cron entry if preferred.

## License

Apache-2.0
