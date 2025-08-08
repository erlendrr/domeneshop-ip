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
    name = "domeneshop-ip",
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

    #[arg(
        long,
        help = "Check and update DNS record if IP has changed (for cron jobs)"
    )]
    check_and_update: bool,
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

#[derive(Serialize, Deserialize, Debug)]
struct AutoUpdateConfig {
    token: String,
    secret: String,
    domain_input: String,
    host: String,
    domain_id: u64,
    record_type: String,
    ttl: u32,
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

fn get_public_ip() -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let public_ip_response = client
        .get("https://ifconfig.me")
        .header("User-Agent", "curl")
        .header("Accept", "text/plain")
        .send()?;

    if !public_ip_response.status().is_success() {
        return Err(format!(
            "Error fetching public IP. Status: {}",
            public_ip_response.status()
        )
        .into());
    }

    Ok(public_ip_response.text()?)
}

fn get_current_dns_record_ip(
    config: &AutoUpdateConfig,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let client = Client::new();
    let dns_url = format!(
        "https://api.domeneshop.no/v0/domains/{}/dns",
        config.domain_id
    );

    let dns_response = client
        .get(&dns_url)
        .basic_auth(&config.token, Some(&config.secret))
        .send()?;

    if !dns_response.status().is_success() {
        return Err(format!(
            "Error fetching DNS records. Status: {}",
            dns_response.status()
        )
        .into());
    }

    let dns_records: Vec<DnsRecord> = dns_response.json()?;

    // Find the specific record we're managing
    let record = dns_records
        .iter()
        .find(|r| r.host == config.host && r.record_type == config.record_type);

    Ok(record.map(|r| r.data.clone()))
}

fn update_dns_record(
    config: &AutoUpdateConfig,
    new_ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    // First, get all DNS records to find the record ID
    let dns_url = format!(
        "https://api.domeneshop.no/v0/domains/{}/dns",
        config.domain_id
    );

    let dns_response = client
        .get(&dns_url)
        .basic_auth(&config.token, Some(&config.secret))
        .send()?;

    if !dns_response.status().is_success() {
        return Err(format!(
            "Error fetching DNS records. Status: {}",
            dns_response.status()
        )
        .into());
    }

    let dns_records: Vec<DnsRecord> = dns_response.json()?;

    // Find the specific record we're managing
    let existing_record = dns_records
        .iter()
        .find(|r| r.host == config.host && r.record_type == config.record_type);

    if let Some(record) = existing_record {
        // Update existing record
        let update = DnsRecordUpdate {
            host: config.host.clone(),
            ttl: config.ttl,
            record_type: config.record_type.clone(),
            data: new_ip.to_string(),
        };

        let update_url = format!(
            "https://api.domeneshop.no/v0/domains/{}/dns/{}",
            config.domain_id, record.id
        );

        let response = client
            .put(&update_url)
            .basic_auth(&config.token, Some(&config.secret))
            .json(&update)
            .send()?;

        if !response.status().is_success() {
            return Err(
                format!("Failed to update DNS record. Status: {}", response.status()).into(),
            );
        }
    } else {
        // Create new record if it doesn't exist
        let new_record = DnsRecordUpdate {
            host: config.host.clone(),
            ttl: config.ttl,
            record_type: config.record_type.clone(),
            data: new_ip.to_string(),
        };

        let create_url = format!(
            "https://api.domeneshop.no/v0/domains/{}/dns",
            config.domain_id
        );

        let response = client
            .post(&create_url)
            .basic_auth(&config.token, Some(&config.secret))
            .json(&new_record)
            .send()?;

        if response.status() != StatusCode::CREATED {
            return Err(
                format!("Failed to create DNS record. Status: {}", response.status()).into(),
            );
        }
    }

    Ok(())
}

fn run_auto_update_check(config_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(|| chrono::Utc::now())
        .format("%Y-%m-%d %H:%M:%S UTC");

    println!("[{}] Starting auto-update check", datetime);

    // Load auto-update configuration
    let config_content = fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read auto-update config: {}", e))?;
    let config: AutoUpdateConfig = serde_json::from_str(&config_content)
        .map_err(|e| format!("Failed to parse auto-update config: {}", e))?;

    // Get current public IP
    let current_public_ip =
        get_public_ip().map_err(|e| format!("Failed to get public IP: {}", e))?;

    // Get current DNS record IP
    let current_dns_ip = get_current_dns_record_ip(&config)
        .map_err(|e| format!("Failed to get current DNS record: {}", e))?;

    match current_dns_ip {
        Some(dns_ip) => {
            if dns_ip.trim() != current_public_ip.trim() {
                println!(
                    "[{}] IP address changed from {} to {}. Updating DNS record...",
                    datetime, dns_ip, current_public_ip
                );
                update_dns_record(&config, &current_public_ip)
                    .map_err(|e| format!("Failed to update DNS record: {}", e))?;
                println!("[{}] DNS record updated successfully!", datetime);
            } else {
                println!(
                    "[{}] IP address unchanged ({}). No update needed.",
                    datetime, current_public_ip
                );
            }
        }
        None => {
            println!(
                "[{}] No existing DNS record found. Creating new record with IP: {}",
                datetime, current_public_ip
            );
            update_dns_record(&config, &current_public_ip)
                .map_err(|e| format!("Failed to create DNS record: {}", e))?;
            println!("[{}] DNS record created successfully!", datetime);
        }
    }

    Ok(())
}

fn add_crontab_entry() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let binary_path = std::env::current_exe()?;
    let cron_entry = format!(
        "* * * * * {} --check-and-update >/dev/null 2>&1",
        binary_path.display()
    );

    // Get current crontab
    let current_crontab = Command::new("crontab").arg("-l").output();

    let mut crontab_content = String::new();

    // If crontab exists, read it
    if let Ok(output) = current_crontab {
        if output.status.success() {
            crontab_content = String::from_utf8_lossy(&output.stdout).to_string();

            // Check if our entry already exists
            if crontab_content.contains("domeneshop-ip --check-and-update") {
                println!("Cron job for domeneshop-ip already exists. Updating...");
                // Remove existing domeneshop-ip entries
                crontab_content = crontab_content
                    .lines()
                    .filter(|line| !line.contains("domeneshop-ip --check-and-update"))
                    .collect::<Vec<_>>()
                    .join("\n");
                if !crontab_content.is_empty() {
                    crontab_content.push('\n');
                }
            }
        }
    }

    // Add our new entry
    crontab_content.push_str(&cron_entry);
    crontab_content.push('\n');

    // Write the updated crontab
    let mut crontab_process = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    if let Some(stdin) = crontab_process.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(crontab_content.as_bytes())?;
    }

    let status = crontab_process.wait()?;

    if !status.success() {
        return Err("Failed to update crontab".into());
    }

    println!("{}", "✓ Cron job added successfully!".green().bold());
    println!("The system will now check for IP changes every minute.");

    Ok(())
}

fn setup_auto_update_config(
    token: &str,
    secret: &str,
    domain_input: &str,
    host: &str,
    domain_id: u64,
    record_type: &str,
    ttl: u32,
    config_dir: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let auto_update_config = AutoUpdateConfig {
        token: token.to_string(),
        secret: secret.to_string(),
        domain_input: domain_input.to_string(),
        host: host.to_string(),
        domain_id,
        record_type: record_type.to_string(),
        ttl,
    };

    let config_path = config_dir.join("auto_update_config.json");
    let config_json = serde_json::to_string_pretty(&auto_update_config)?;
    fs::write(&config_path, config_json)?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
    }

    println!(
        "Auto-update configuration saved to {}",
        config_path.display()
    );

    // Automatically add crontab entry
    println!("\n{}", "Setting up automatic IP monitoring...".yellow());
    match add_crontab_entry() {
        Ok(()) => {
            println!("{}", "Auto-update setup complete!".green().bold());
            println!("\nTo manage your cron job later:");
            println!("• View cron jobs:    {}", "crontab -l".yellow());
            println!("• Edit cron jobs:    {}", "crontab -e".yellow());
            println!("• Remove cron jobs:  {}", "crontab -r".yellow());
            println!(
                "• Test auto-update:  {}",
                format!(
                    "{} --check-and-update",
                    std::env::current_exe().unwrap().display()
                )
                .yellow()
            );
        }
        Err(e) => {
            println!("{}", "Failed to set up cron job automatically.".yellow());
            println!("Error: {}", e);
            println!("You can set it up manually by running:");
            println!(
                "{}",
                format!(
                    "echo '* * * * * {} --check-and-update' | crontab -",
                    std::env::current_exe()?.display()
                )
                .yellow()
            );
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments first - Clap will automatically handle --help
    let cli = Cli::parse();

    // Determine configuration directory
    let config_dir: PathBuf = match dirs::config_local_dir() {
        Some(dir) => dir.join("domeneshop"),
        None => PathBuf::from("./domeneshop_config"),
    };
    fs::create_dir_all(&config_dir)?;

    // Handle check-and-update mode (for cron jobs)
    if cli.check_and_update {
        let auto_update_config_path = config_dir.join("auto_update_config.json");
        if !auto_update_config_path.exists() {
            eprintln!(
                "Auto-update configuration not found. Please run the tool in interactive mode first to set up auto-update."
            );
            return Ok(());
        }

        return match run_auto_update_check(&auto_update_config_path) {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("Auto-update check failed: {}", e);
                std::process::exit(1);
            }
        };
    }

    let theme = ColorfulTheme::default();
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
    let public_ip = get_public_ip()?;
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
    let selected_ip = if cli.yes {
        public_ip.clone()
    } else {
        Input::<String>::with_theme(&theme)
            .with_prompt("Enter the IP address to use")
            .default(public_ip.clone())
            .interact_text()?
    };

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

    let mut dns_updated = false;
    let mut final_ttl = 3600u32; // Default TTL
    let mut auto_update_enabled = false;

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

        final_ttl = record.ttl; // Use existing TTL

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
                    dns_updated = true;
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
                    dns_updated = true;
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
            dns_updated = true;
        } else {
            eprintln!("Failed to create DNS record. Status: {}", response.status());
            if let Ok(error_text) = response.text() {
                eprintln!("Error: {}", error_text);
            }
        }
    }

    // Ask about auto-update if DNS was successfully updated
    if dns_updated {
        let setup_auto_update = if cli.yes {
            false
        } else {
            Confirm::with_theme(&theme)
                .with_prompt(
                    "Do you want to enable automatic DNS record updates when your IP changes?",
                )
                .default(false)
                .interact()?
        };

        if setup_auto_update {
            setup_auto_update_config(
                &token,
                &secret,
                &domain_input,
                &host,
                top_level_domain.id,
                record_type,
                final_ttl,
                &config_dir,
            )?;
            auto_update_enabled = true;
        }
    }

    // Save credentials automatically if auto-update is enabled, otherwise ask
    if !use_saved_config {
        let save_creds = if auto_update_enabled {
            println!("Auto-update enabled - automatically saving credentials for future use.");
            true
        } else if cli.yes {
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

    Ok(())
}
