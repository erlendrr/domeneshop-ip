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
--help                     Show help information
--version                  Show version information
```

## Features

- Automatically detects your public IP address
- Lists available network interfaces
- Updates DNS A or AAAA records at Domeneshop
- Stores API credentials securely for future use
- Interactive mode with confirmation prompts

## License

Apache-2.0
