/*
Copyright 2025 Erlend Ryan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use clap::Parser;
use dialoguer::{Confirm, Input, Password, theme::ColorfulTheme};
use dotenvy;
use pnet::datalink;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "domeneshop-cli",
    author = "Erlend Ryan",
    version,
    about = "Manage Domeneshop domains via CLI"
)]
struct Cli {
    #[arg(long, env = "DOMENESHOP_API_TOKEN")]
    token: Option<String>,

    #[arg(long, env = "DOMENESHOP_API_SECRET", hide_env_values = true)]
    secret: Option<String>,

    #[arg(long, help = "Domain to manage (e.g. example.com or sub.example.com")]
    domain_input: Option<String>,

    #[arg(short = 'y', long = "yes", help = "Skip all confirmation prompts")]
    yes: bool,
}

#[derive(Deserialize, Debug)]
struct Domain {
    id: u64,
    domain: String,
}

#[derive(Deserialize, Debug)]
struct DnsRecord {
    id: u64,
    host: String,
    ttl: u32,
    #[serde(rename = "type")]
    record_type: String,
    data: String,
}

fn validate_domain_input(input: &str, domains: &[Domain]) -> Result<(String, u64), &'static str> {
    // Check for direct domain match
    if let Some(domain) = domains.iter().find(|d| d.domain == input) {
        return Ok((input.to_string(), domain.id));
    }

    // Check for subdomain match
    for domain in domains {
        if input.ends_with(&format!(".{}", domain.domain)) {
            return Ok((input.to_string(), domain.id));
        }
    }

    Err("You don't own this domain. Please enter a domain you own or a subdomain of it.")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments first - Clap will automatically handle --help
    let cli = Cli::parse();

    let theme = ColorfulTheme::default();

    // Determine configuration directory:
    // On Unix, we'll use the standard config directory (~/.config/domeneshop/.env).
    // On failure, fallback to a local directory.
    let config_dir: PathBuf = match dirs::config_local_dir() {
        Some(dir) => dir.join("domeneshop"),
        None => PathBuf::from("./domeneshop_config"),
    };
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join(".env");

    // Only load the saved config if credentials are not provided via CLI
    let mut use_saved_config: bool = false;
    if (cli.token.is_none() || cli.secret.is_none()) && config_path.exists() {
        if cli.yes {
            use_saved_config = true;
            println!("Using saved credentials from {}", config_path.display());
        } else {
            use_saved_config = Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Found configuration at {}. Use saved credentials?",
                    config_path.display()
                ))
                .default(true)
                .interact()?;
        }
    }
    if use_saved_config {
        dotenvy::from_path(&config_path).ok();
    }

    // Get token and secret from CLI args or prompt
    let token = match cli
        .token
        .or_else(|| std::env::var("DOMENESHOP_API_TOKEN").ok())
    {
        Some(t) => t,
        None => Input::with_theme(&theme)
            .with_prompt("Enter Domeneshop API Token")
            .interact_text()?,
    };

    let secret = match cli
        .secret
        .or_else(|| std::env::var("DOMENESHOP_API_SECRET").ok())
    {
        Some(s) => s,
        None => Password::with_theme(&theme)
            .with_prompt("Enter Domeneshop API Secret")
            .interact()?,
    };

    // Validate authentication before saving
    let client = Client::new();

    let domains_url = "https://api.domeneshop.no/v0/domains";

    println!("Authenticating to Domeneshop API by fetching domains...");

    let auth_test = client
        .get(domains_url)
        .basic_auth(&token, Some(&secret))
        .send()?;

    if !auth_test.status().is_success() {
        eprintln!(
            "Authentication failed. Status: {}. Please check your credentials and try again.",
            auth_test.status()
        );
        return Ok(());
    }
    if !use_saved_config {
        let save_creds = if cli.yes {
            false
        } else {
            Confirm::with_theme(&theme)
                .with_prompt("Do you want to save your credentials for future use?")
                .default(false)
                .interact()?
        };
        if save_creds {
            let mut file = fs::File::create(&config_path)?;
            writeln!(file, "DOMENESHOP_API_TOKEN={}", token)?;
            writeln!(file, "DOMENESHOP_API_SECRET={}", secret)?;
            // On Unix, restrict permissions to owner-read/write only.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
            }
            println!("Credentials saved to {}", config_path.display());
        }
    }

    // Reuse the response from the auth test instead of making a second request
    let response = auth_test;

    let domains: Vec<Domain> = response.json()?;
    if domains.is_empty() {
        println!("No domains found in your account.");
        return Ok(());
    }

    let domain_names: Vec<String> = domains.iter().map(|d| d.domain.clone()).collect();
    // Display all available domains to the user
    println!("\nAvailable domains:");
    for domain in &domain_names {
        println!("  - {}", domain);
    }

    // Ask the user to input a domain or subdomain
    let mut top_level_domain_id = None;

    let domain_input = match &cli.domain_input {
        Some(input) => match validate_domain_input(input, &domains) {
            Ok((input_str, domain_id)) => {
                top_level_domain_id = Some(domain_id);
                input_str
            }
            Err(err) => {
                println!("{}", err);
                return Ok(());
            }
        },
        None => Input::with_theme(&theme)
            .with_prompt("Enter a domain or subdomain (e.g. example.com or sub.example.com)")
            .validate_with(|input: &String| -> Result<(), &str> {
                match validate_domain_input(input, &domains) {
                    Ok((_, domain_id)) => {
                        top_level_domain_id = Some(domain_id);
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            })
            .interact_text()?,
    };

    let top_level_domain = domains
        .iter()
        .find(|d| d.id == top_level_domain_id.expect("Domain ID not found"))
        .expect("Domain not found");

    println!("Getting DNS records for {}...", top_level_domain.domain);

    // Fetch DNS records for the selected domain.
    let dns_url = format!(
        "https://api.domeneshop.no/v0/domains/{}/dns",
        top_level_domain.id
    );

    let dns_response = client
        .get(&dns_url)
        .basic_auth(&token, Some(&secret))
        .send()?;

    if !dns_response.status().is_success() {
        eprintln!(
            "Error fetching DNS records. Status: {}",
            dns_response.status()
        );
        return Ok(());
    }

    let dns_records: Vec<DnsRecord> = dns_response.json()?;
    if dns_records.is_empty() {
        println!("No DNS records found for the domain.");
    } else {
        println!("\nDNS Records for {}:", top_level_domain.domain);
        for rec in dns_records {
            // If host is "@", it represents the root domain.
            let full_host = if rec.host == "@" {
                top_level_domain.domain.clone()
            } else {
                format!("{}.{}", rec.host, top_level_domain.domain)
            };
            println!(
                "ID: {} | Host: {} | Type: {} | Data: {} | TTL: {}",
                rec.id, full_host, rec.record_type, rec.data, rec.ttl
            );
        }
    }

    let interfaces = datalink::interfaces();
    let interfaces_with_ip = interfaces
        .into_iter()
        .filter(|iface| !iface.ips.is_empty())
        .collect::<Vec<_>>();

    println!("");
    if interfaces_with_ip.is_empty() {
        println!("No network interfaces with IP addresses found.");
    } else {
        println!("Network interfaces with IP addresses:");
        for iface in &interfaces_with_ip {
            println!(
                "{} {}:",
                iface.name,
                iface.mac.expect("MAC address not found")
            );
            for ip in &iface.ips {
                println!("  - IP Address: {}", ip);
            }
        }
    }

    Ok(())
}
