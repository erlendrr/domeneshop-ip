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
use colored::*;
use dialoguer::{Confirm, Input, Password, theme::ColorfulTheme};
use dotenvy;
use pnet::datalink;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
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

#[derive(Serialize, Debug)]
struct DnsRecordUpdate {
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

fn parse_domain_input(input: &str, top_level_domain: &str) -> (String, String) {
    if input == top_level_domain {
        // Root domain
        return ("@".to_string(), top_level_domain.to_string());
    }

    // For subdomains
    if input.ends_with(&format!(".{}", top_level_domain)) {
        let host = input
            .trim_end_matches(&format!(".{}", top_level_domain))
            .to_string();
        return (host, top_level_domain.to_string());
    }

    // Default fallback (shouldn't reach here if validation works)
    (input.to_string(), top_level_domain.to_string())
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
        for rec in &dns_records {
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

    // Parse the domain input to get the host part
    let (host, domain_part) = parse_domain_input(&domain_input, &top_level_domain.domain);
    println!("Host: {}, Domain: {}", host, domain_part);

    // Get the public IP address from ifconfig.me
    println!("Fetching public IP address from ifconfig.me...");
    let public_ip_response = client
        .get("https://ifconfig.me")
        .header("User-Agent", "curl") // Simulate curl to get plain text response
        .header("Accept", "text/plain")
        .send()?;

    if !public_ip_response.status().is_success() {
        eprintln!(
            "Error fetching public IP. Status: {}",
            public_ip_response.status()
        );
        return Ok(());
    }

    let public_ip = public_ip_response.text()?;
    println!("Public IP address from ifconfig.me: {}", public_ip);

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
                let ip_str = ip.to_string();
                // Extract just the IP part without the subnet mask
                let ip_only = ip_str.split('/').next().unwrap_or("");

                if ip_only == public_ip {
                    println!(
                        "  - IP Address: {} {}",
                        ip.to_string().green().bold(),
                        "(PUBLIC IP MATCH ✓)".green().bold()
                    );
                } else {
                    println!("  - IP Address: {}", ip);
                }
            }
        }
    }

    // Prompt user for IP selection with public IP as default
    let selected_ip = Input::<String>::with_theme(&theme)
        .with_prompt("Enter the IP address to use")
        .default(public_ip.clone())
        .interact_text()?;

    println!("Selected IP address: {}", selected_ip);

    // After getting selected IP, check for existing DNS records
    let existing_record = dns_records
        .iter()
        .find(|r| r.host == host && (r.record_type == "A" || r.record_type == "AAAA"));

    // Determine if we're updating an IPv4 or IPv6 address
    let record_type = if selected_ip.contains(':') {
        "AAAA"
    } else {
        "A"
    };

    if let Some(record) = existing_record {
        println!("\n{}", "Existing DNS record found:".yellow().bold());
        println!(
            "ID: {} | Host: {} | Type: {} | IP: {} | TTL: {}",
            record.id,
            if record.host == "@" {
                top_level_domain.domain.clone()
            } else {
                format!("{}.{}", record.host, top_level_domain.domain)
            },
            record.record_type,
            record.data,
            record.ttl
        );

        let should_update = if cli.yes {
            true
        } else {
            Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Do you want to update this record to point to {}?",
                    selected_ip
                ))
                .default(true)
                .interact()?
        };

        if should_update {
            // Check if record type needs to change (A vs AAAA)
            let type_change_needed = record.record_type != record_type;

            if type_change_needed {
                // Need to delete existing record and create a new one
                println!(
                    "Record type needs to change from {} to {}. Deleting old record...",
                    record.record_type, record_type
                );

                // Delete the existing record
                let delete_url = format!(
                    "https://api.domeneshop.no/v0/domains/{}/dns/{}",
                    top_level_domain.id, record.id
                );

                let delete_response = client
                    .delete(&delete_url)
                    .basic_auth(&token, Some(&secret))
                    .send()?;

                if !delete_response.status().is_success() {
                    eprintln!(
                        "Failed to delete old DNS record. Status: {}",
                        delete_response.status()
                    );
                    if let Ok(error_text) = delete_response.text() {
                        eprintln!("Error: {}", error_text);
                    }
                    return Ok(());
                }

                println!("Creating new record with updated type...");

                // Create new record
                let new_record = DnsRecordUpdate {
                    host: host.clone(),
                    ttl: record.ttl,
                    record_type: record_type.to_string(),
                    data: selected_ip.clone(),
                };

                let create_url = format!(
                    "https://api.domeneshop.no/v0/domains/{}/dns",
                    top_level_domain.id
                );

                let create_response = client
                    .post(&create_url)
                    .basic_auth(&token, Some(&secret))
                    .json(&new_record)
                    .send()?;

                if create_response.status() == StatusCode::CREATED {
                    println!("{}", "DNS record created successfully!".green().bold());
                } else {
                    eprintln!(
                        "Failed to create new DNS record. Status: {}",
                        create_response.status()
                    );
                    if let Ok(error_text) = create_response.text() {
                        eprintln!("Error: {}", error_text);
                    }
                }
            } else {
                // Same record type, can update normally
                // Create update payload
                let update = DnsRecordUpdate {
                    host: host.clone(),
                    ttl: record.ttl,
                    record_type: record.record_type.clone(), // Use existing record type
                    data: selected_ip.clone(),
                };

                // Send update request
                println!("Updating DNS record...");
                let update_url = format!(
                    "https://api.domeneshop.no/v0/domains/{}/dns/{}",
                    top_level_domain.id, record.id
                );

                let response = client
                    .put(&update_url)
                    .basic_auth(&token, Some(&secret))
                    .json(&update)
                    .send()?;

                if response.status().is_success() {
                    println!("{}", "DNS record updated successfully!".green().bold());
                } else {
                    eprintln!("Failed to update DNS record. Status: {}", response.status());
                    if let Ok(error_text) = response.text() {
                        eprintln!("Error: {}", error_text);
                    }
                }
            }
        } else {
            println!("Update cancelled.");
        }
    } else {
        // No existing record, create a new one
        println!(
            "\n{}",
            "No existing DNS record found. Creating new record...".yellow()
        );

        // Create new record payload
        let new_record = DnsRecordUpdate {
            host: host.clone(),
            ttl: 3600, // Default TTL
            record_type: record_type.to_string(),
            data: selected_ip.clone(),
        };

        // Send create request
        let create_url = format!(
            "https://api.domeneshop.no/v0/domains/{}/dns",
            top_level_domain.id
        );

        let response = client
            .post(&create_url)
            .basic_auth(&token, Some(&secret))
            .json(&new_record)
            .send()?;

        if response.status() == StatusCode::CREATED {
            println!("{}", "DNS record created successfully!".green().bold());
        } else {
            eprintln!("Failed to create DNS record. Status: {}", response.status());
            if let Ok(error_text) = response.text() {
                eprintln!("Error: {}", error_text);
            }
        }
    }

    Ok(())
}
