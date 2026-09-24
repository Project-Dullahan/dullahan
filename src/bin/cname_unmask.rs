use std::env;
use std::fs;
use std::path::Path;
use std::io::{self, Write};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use reqwest::blocking::Client;
use std::time::Duration;

#[path = "../cartograph.rs"]
mod cartograph;

const KNOWN_AD_TRACKER_DOMAINS: &[&str] = &[
    "doubleclick.net", "googlesyndication.com", "google-analytics.com",
    "googletagmanager.com", "connect.facebook.net", "adnxs.com", 
    "taboola.com", "criteo.com", "amazon-adsystem.com", "demdex.net",
];

enum ExportFormat {
    Hosts,
    PiHole,
    Dnsmasq,
    Json,
}

fn check_http_intel(client: &Client, domain: &str) -> (Vec<String>, usize) {
    let mut missing_headers = Vec::new();
    let mut tracker_count = 0;
    
    let url = format!("http://{}", domain);
    if let Ok(resp) = client.get(&url).send() {
        let headers = resp.headers();
        if !headers.contains_key("content-security-policy") { missing_headers.push("CSP".to_string()); }
        if !headers.contains_key("strict-transport-security") { missing_headers.push("HSTS".to_string()); }
        if !headers.contains_key("x-frame-options") { missing_headers.push("X-Frame".to_string()); }
        
        if KNOWN_AD_TRACKER_DOMAINS.iter().any(|t| domain.contains(t)) {
            tracker_count += 1;
        }
    } else {
        missing_headers.push("OFFLINE".to_string());
    }
    
    (missing_headers, tracker_count)
}

fn export_blocklist(file_path: &str, format: ExportFormat) {
    let file_content = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            std::process::exit(1);
        }
    };

    let resolver = match Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error initializing resolver: {}", e);
            std::process::exit(1);
        }
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .user_agent("Mozilla/5.0 Dullahan/0.1 Security Audit")
        .build()
        .unwrap();

    let mut high_risk_domains = Vec::new();

    println!("[DULLAHAN] Analyzing domains for export...");

    for line in file_content.lines() {
        let mut target_host = line.trim().to_string();
        if target_host.is_empty() || target_host.starts_with('#') { continue; }
        
        target_host = target_host.replace("https://", "").replace("http://", "").replace("://", "");
        if let Some(pos) = target_host.find('/') { target_host = target_host[..pos].to_string(); }

        println!("  Checking: {}", target_host);

        if resolver.lookup_ip(&target_host).is_ok() {
            let (missing_headers, _) = check_http_intel(&client, &target_host);
            
            // Only export HIGH RISK domains (3+ missing headers or OFFLINE)
            if missing_headers.len() >= 3 || missing_headers.contains(&"OFFLINE".to_string()) {
                high_risk_domains.push(target_host);
            }
        }
    }

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    match format {
        ExportFormat::Hosts => {
            writeln!(handle, "# Dullahan Blocklist - Generated {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")).unwrap();
            writeln!(handle, "# Format: hosts file (0.0.0.0 domain)").unwrap();
            writeln!(handle, "# Count: {} domains", high_risk_domains.len()).unwrap();
            writeln!(handle).unwrap();
            for domain in &high_risk_domains {
                writeln!(handle, "0.0.0.0 {}", domain).unwrap();
            }
        }
        ExportFormat::PiHole => {
            writeln!(handle, "# Dullahan Blocklist - Pi-hole Format").unwrap();
            writeln!(handle, "# Count: {} domains", high_risk_domains.len()).unwrap();
            writeln!(handle).unwrap();
            for domain in &high_risk_domains {
                writeln!(handle, "{}", domain).unwrap();
            }
        }
        ExportFormat::Dnsmasq => {
            writeln!(handle, "# Dullahan Blocklist - dnsmasq Format").unwrap();
            writeln!(handle, "# Count: {} domains", high_risk_domains.len()).unwrap();
            writeln!(handle).unwrap();
            for domain in &high_risk_domains {
                writeln!(handle, "address=/{}/0.0.0.0", domain).unwrap();
            }
        }
        ExportFormat::Json => {
            let json = serde_json::json!({
                "generated": chrono::Local::now().to_rfc3339(),
                "blocked_domains": high_risk_domains,
                "count": high_risk_domains.len(),
                "format": "json",
                "tool": "Dullahan"
            });
            writeln!(handle, "{}", serde_json::to_string_pretty(&json).unwrap()).unwrap();
        }
    }

    eprintln!("\n[SUCCESS] Exported {} high-risk domains", high_risk_domains.len());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Check for export mode
    if args.len() >= 3 && args[1] == "--export" {
        let format = match args[2].as_str() {
            "hosts" => ExportFormat::Hosts,
            "pihole" => ExportFormat::PiHole,
            "dnsmasq" => ExportFormat::Dnsmasq,
            "json" => ExportFormat::Json,
            _ => {
                eprintln!("Unknown export format: {}", args[2]);
                eprintln!("Supported formats: hosts, pihole, dnsmasq, json");
                std::process::exit(1);
            }
        };
        
        let file_path = if args.len() > 3 { &args[3] } else {
            eprintln!("Usage: cname_unmask --export <format> <targets.txt>");
            eprintln!("Formats: hosts, pihole, dnsmasq, json");
            std::process::exit(1);
        };
        
        export_blocklist(file_path, format);
        return;
    }
    
    // Normal mode
    if args.len() != 2 {
        eprintln!("Usage: cname_unmask <targets.txt>");
        eprintln!("       cname_unmask --export <format> <targets.txt>");
        eprintln!("Example: ./cname_unmask lists/global_aid.txt");
        eprintln!("Example: ./cname_unmask --export hosts lists/global_aid.txt > blocklist.txt");
        std::process::exit(1);
    }

    let file_path = &args[1];
    
    if !Path::new(file_path).exists() {
        eprintln!("Error: Target list file not found at '{}'", file_path);
        eprintln!("Hint: Create a 'lists/' directory or provide a valid path.");
        std::process::exit(1);
    }

    let file_content = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => { 
            eprintln!("Error: Could not read target list. ({})", e); 
            std::process::exit(1); 
        }
    };

    println!("[DULLAHAN] Initiating deep reconnaissance pass...");
    println!("Reading targets from: {}\n", file_path);
    
    let resolver = match Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Failed to initialize DNS resolver. ({})", e);
            std::process::exit(1);
        }
    };
        
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .user_agent("Mozilla/5.0 Dullahan/0.1 Security Audit")
        .build()
        .unwrap();

    let mut intel_data: Vec<cartograph::DomainIntel> = Vec::new();

    for line in file_content.lines() {
        let mut target_host = line.trim().to_string();
        if target_host.is_empty() || target_host.starts_with('#') { continue; }
        
        target_host = target_host.replace("https://", "").replace("http://", "").replace("://", "");
        if let Some(pos) = target_host.find('/') { target_host = target_host[..pos].to_string(); }

        println!("Probing: {}", target_host);
        
        match resolver.lookup_ip(&target_host) {
            Ok(lookup) => {
                let (missing_headers, tracker_count) = check_http_intel(&client, &target_host);
                
                for ip in lookup.iter() {
                    let ip_str = ip.to_string();
                    println!("  -> IP: {} | Headers Missing: {} | Trackers: {}", ip_str, missing_headers.len(), tracker_count);
                    
                    let (risk_level, color) = if missing_headers.contains(&"OFFLINE".to_string()) {
                        ("OFFLINE / UNREACHABLE".to_string(), "#888888".to_string())
                    } else if missing_headers.len() >= 3 {
                        ("HIGH RISK: Severely Degraded Defenses".to_string(), "#ff0033".to_string())
                    } else if target_host.contains("cloudflare") || target_host.contains("akamai") {
                        ("OBFUSCATED (CDN)".to_string(), "#ffaa00".to_string())
                    } else {
                        ("NEUTRAL".to_string(), "#00ff41".to_string())
                    };

                    intel_data.push(cartograph::DomainIntel {
                        domain: target_host.clone(),
                        ip: ip_str,
                        lat: 0.0, lon: 0.0,
                        country: "".to_string(), city: "".to_string(),
                        isp: "Unknown (GeoLite2 Free)".to_string(),
                        risk_level, color,
                        missing_headers: missing_headers.clone(),
                        tracker_count,
                    });
                }
            }
            Err(e) => println!("  -> DNS Resolution Failed: {}", e),
        }
    }

    let geo_db_path = match dirs::home_dir() {
        Some(h) => h.join(".local/share/dullahan/geo/GeoLite2-City.mmdb").to_string_lossy().to_string(),
        None => {
            eprintln!("Error: Could not determine home directory for GeoLite database.");
            eprintln!("Please set the HOME environment variable or run from a standard user account.");
            std::process::exit(1);
        }
    };

    let output_path = "dullahan_batch_recon_map.html";
    cartograph::generate_offline_threat_map(intel_data, output_path, &geo_db_path);
}
