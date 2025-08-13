use clap::Parser;
use colored::*;
use dialoguer::{Confirm, Input, Password, theme::ColorfulTheme};
use dotenvy;
use pnet::datalink;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

    #[arg(
        long,
        help = "Path or name of the auto-update config to use. If a name is given, it will be looked up under the config dir."
    )]
    config: Option<String>,

    #[arg(
        long,
        help = "Run check-and-update for all saved configs (one per domain/record)"
    )]
    all: bool,
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

fn add_crontab_entry_for_config(
    config_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let binary_path = std::env::current_exe()?;
    let cron_entry = format!(
        "* * * * * {} --check-and-update --config '{}' >/dev/null 2>&1",
        binary_path.display(),
        config_path.display()
    );

    // Get current crontab
    let current_crontab = Command::new("crontab").arg("-l").output();

    let mut crontab_content = String::new();

    // If crontab exists, read it
    if let Ok(output) = current_crontab {
        if output.status.success() {
            crontab_content = String::from_utf8_lossy(&output.stdout).to_string();
            // If the exact entry exists, do nothing; otherwise, ensure we don't duplicate similar entries for the same config
            let exists_for_config = crontab_content.lines().any(|line| {
                line.contains("domeneshop-ip --check-and-update")
                    && line.contains(&config_path.display().to_string())
            });
            if exists_for_config {
                println!("Cron job for this config already exists. Skipping add.");
                return Ok(());
            }
            if !crontab_content.is_empty() && !crontab_content.ends_with('\n') {
                crontab_content.push('\n');
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
    println!("The system will now check for IP changes every minute for this config.");

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

    // Store one config per record under auto_update/ directory
    let auto_update_dir = config_dir.join("auto_update");
    fs::create_dir_all(&auto_update_dir)?;

    // Build a readable, unique filename: <fqdn>__<type>.json
    let fqdn = domain_input.to_string();
    let sanitized = fqdn.replace('/', "_");
    let file_name = format!("{}__{}.json", sanitized, record_type);
    let config_path = auto_update_dir.join(file_name);
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
    println!(
        "\n{}",
        "Setting up automatic IP monitoring for this domain/record...".yellow()
    );
    match add_crontab_entry_for_config(&config_path) {
        Ok(()) => {
            println!("{}", "Auto-update setup complete!".green().bold());
            println!("\nTo manage your cron job later:");
            println!("• View cron jobs:    {}", "crontab -l".yellow());
            println!("• Edit cron jobs:    {}", "crontab -e".yellow());
            println!("• Remove cron jobs:  {}", "crontab -r".yellow());
            println!(
                "• Test auto-update:  {}",
                format!(
                    "{} --check-and-update --config '{}'",
                    std::env::current_exe().unwrap().display(),
                    config_path.display()
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
                    "echo '* * * * * {} --check-and-update --config \"{}\"' | crontab -",
                    std::env::current_exe()?.display(),
                    config_path.display()
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
        // New multi-config location
        let auto_update_dir = config_dir.join("auto_update");

        // Helper to run one config
        let run_one = |path: PathBuf| -> Result<(), Box<dyn std::error::Error>> {
            match run_auto_update_check(&path) {
                Ok(()) => Ok(()),
                Err(e) => {
                    Err(format!("Auto-update check failed for {}: {}", path.display(), e).into())
                }
            }
        };

        if cli.all {
            // Iterate all configs under auto_update/*.json
            if auto_update_dir.exists() {
                let mut any = false;
                for entry in fs::read_dir(&auto_update_dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("json") {
                        any = true;
                        if let Err(e) = run_one(path.clone()) {
                            eprintln!("{}", e);
                        }
                    }
                }
                if !any {
                    eprintln!(
                        "No auto-update configs found in {}",
                        auto_update_dir.display()
                    );
                }
                return Ok(());
            } else {
                eprintln!(
                    "No auto-update directory found at {}",
                    auto_update_dir.display()
                );
                return Ok(());
            }
        }

        if let Some(cfg) = cli.config {
            // Accept absolute/relative path, or name under auto_update, optionally without .json
            let mut path = PathBuf::from(&cfg);
            if !path.exists() {
                let mut candidate = auto_update_dir.join(&cfg);
                if !candidate.exists() {
                    // Try adding .json
                    candidate.set_extension("json");
                }
                path = candidate;
            }
            if !path.exists() {
                eprintln!(
                    "Config not found: {}\nLooked under {}",
                    cfg,
                    auto_update_dir.display()
                );
                std::process::exit(1);
            }
            return run_one(path).map(|_| ());
        }

        // Legacy single-config support or auto-pick when only one exists
        let legacy_path = config_dir.join("auto_update_config.json");
        if legacy_path.exists() {
            return run_one(legacy_path).map(|_| ());
        }

        // If exactly one config exists under auto_update, use it
        if auto_update_dir.exists() {
            let jsons: Vec<_> = fs::read_dir(&auto_update_dir)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                .collect();
            if jsons.len() == 1 {
                return run_one(jsons[0].clone()).map(|_| ());
            }

            eprintln!(
                "Multiple configs found. Use --config <name|path> or --all. Available configs:"
            );
            for p in jsons {
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    eprintln!("  - {}", name);
                }
            }
        } else {
            eprintln!(
                "Auto-update configuration not found. Run interactive setup to create configs."
            );
        }
        return Ok(());
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
    println!("\nAvailable domains:");
    for domain in &domain_names {
        println!("  - {}", domain);
    }

    // Gather one or more domain inputs
    let raw_inputs = match &cli.domain_input {
        Some(input) => input.clone(),
        None => Input::with_theme(&theme)
            .with_prompt("Enter one or more domains/subdomains (comma or space separated)")
            .validate_with(|raw: &String| -> Result<(), &str> {
                let items: Vec<_> = raw
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                    .collect();
                if items.is_empty() { return Err("Please enter at least one domain."); }
                for s in &items {
                    if validate_domain_input(s, &domains).is_err() {
                        return Err("You don't own one of these domains. Ensure each is owned by your account.");
                    }
                }
                Ok(())
            })
            .interact_text()?,
    };

    let input_domains: Vec<String> = raw_inputs
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_string())
        .collect();

    // Map each input to its top-level domain id
    let mut selections: Vec<(String, u64)> = Vec::new();
    for s in &input_domains {
        match validate_domain_input(s, &domains) {
            Ok((inp, id)) => selections.push((inp, id)),
            Err(err) => {
                println!("{} -> {}", s, err);
                return Ok(());
            }
        }
    }

    // Build domain_id -> Domain lookup
    let mut domain_by_id: HashMap<u64, &Domain> = HashMap::new();
    for d in &domains {
        domain_by_id.insert(d.id, d);
    }

    // Fetch DNS records once per domain_id
    let mut dns_map: HashMap<u64, Vec<DnsRecord>> = HashMap::new();
    for (_, did) in selections
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
    {
        let dns_url = format!("https://api.domeneshop.no/v0/domains/{}/dns", did);
        let dns_response = client
            .get(&dns_url)
            .basic_auth(&token, Some(&secret))
            .send()?;
        if !dns_response.status().is_success() {
            eprintln!(
                "Error fetching DNS records for domain id {}. Status: {}",
                did,
                dns_response.status()
            );
            return Ok(());
        }
        let recs: Vec<DnsRecord> = dns_response.json()?;
        dns_map.insert(did, recs);
    }

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

    // Prompt user for IP selection with public IP as default (applies to all)
    let selected_ip = if cli.yes {
        public_ip.clone()
    } else {
        Input::<String>::with_theme(&theme)
            .with_prompt("Enter the IP address to use for all selected hosts")
            .default(public_ip.clone())
            .interact_text()?
    };

    println!("Selected IP address: {}", selected_ip);

    // Determine record type once for chosen IP
    let record_type = if selected_ip.contains(':') {
        "AAAA"
    } else {
        "A"
    };

    // Track configs for optional auto-update
    struct PlannedConfig {
        domain_input: String,
        host: String,
        domain_id: u64,
        ttl: u32,
    }
    let mut planned: Vec<PlannedConfig> = Vec::new();

    // Process each input domain
    for (domain_input, dom_id) in &selections {
        let top = match domain_by_id.get(dom_id) {
            Some(d) => d,
            None => {
                eprintln!("Domain not found for id {}", dom_id);
                continue;
            }
        };
        let (host, _domain_part) = parse_domain_input(domain_input, &top.domain);

        // Find existing record in cache
        let empty: Vec<DnsRecord> = Vec::new();
        let dns_records_ref = dns_map.get(dom_id);
        let dns_records: &Vec<DnsRecord> = match dns_records_ref {
            Some(v) => v,
            None => &empty,
        };
        let existing_record = dns_records
            .iter()
            .find(|r| r.host == host && (r.record_type == "A" || r.record_type == "AAAA"));

        let mut ttl_use = 3600u32;
        if let Some(record) = existing_record {
            println!("\n{}", "Existing DNS record found:".yellow().bold());
            println!(
                "ID: {} | Host: {} | Type: {} | IP: {} | TTL: {}",
                record.id,
                if record.host == "@" {
                    top.domain.clone()
                } else {
                    format!("{}.{}", record.host, top.domain)
                },
                record.record_type,
                record.data,
                record.ttl
            );
            ttl_use = record.ttl;

            let should_update = if cli.yes {
                true
            } else {
                Confirm::with_theme(&theme)
                    .with_prompt(format!("Update {} to {}?", domain_input, selected_ip))
                    .default(true)
                    .interact()?
            };

            if should_update {
                let type_change_needed = record.record_type != record_type;

                if type_change_needed {
                    println!(
                        "Changing record type from {} to {} for {}...",
                        record.record_type, record_type, domain_input
                    );
                    let delete_url = format!(
                        "https://api.domeneshop.no/v0/domains/{}/dns/{}",
                        top.id, record.id
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
                        continue;
                    }
                    let new_record = DnsRecordUpdate {
                        host: host.clone(),
                        ttl: record.ttl,
                        record_type: record_type.to_string(),
                        data: selected_ip.clone(),
                    };
                    let create_url = format!("https://api.domeneshop.no/v0/domains/{}/dns", top.id);
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
                    let update = DnsRecordUpdate {
                        host: host.clone(),
                        ttl: record.ttl,
                        record_type: record.record_type.clone(),
                        data: selected_ip.clone(),
                    };
                    let update_url = format!(
                        "https://api.domeneshop.no/v0/domains/{}/dns/{}",
                        top.id, record.id
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
                println!("Update cancelled for {}.", domain_input);
            }
        } else {
            println!(
                "\n{} {}",
                "No existing DNS record found. Creating new record for".yellow(),
                domain_input
            );
            let new_record = DnsRecordUpdate {
                host: host.clone(),
                ttl: 3600,
                record_type: record_type.to_string(),
                data: selected_ip.clone(),
            };
            let create_url = format!("https://api.domeneshop.no/v0/domains/{}/dns", top.id);
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

        planned.push(PlannedConfig {
            domain_input: domain_input.clone(),
            host,
            domain_id: *dom_id,
            ttl: ttl_use,
        });
    }

    // Offer auto-update for all selected hosts
    if !planned.is_empty() {
        let setup_auto_update = if cli.yes {
            false
        } else {
            Confirm::with_theme(&theme)
                .with_prompt("Enable automatic DNS updates for all selected hosts?")
                .default(false)
                .interact()?
        };
        if setup_auto_update {
            for p in planned {
                let _ = setup_auto_update_config(
                    &token,
                    &secret,
                    &p.domain_input,
                    &p.host,
                    p.domain_id,
                    record_type,
                    p.ttl,
                    &config_dir,
                );
            }
        }
    }
    // Save credentials choice
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
