mod forensics;
mod metadata;
mod scanner;
mod web_server;

use maxminddb::geoip2::City;
use maxminddb::Reader;
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::net::ToSocketAddrs; // NEW: Added to resolve domains to IPs
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
enum DomainTag {
    Safe,
    Malicious,
    Investigate,
    None,
}

#[derive(Clone, PartialEq)]
enum RiskLevel {
    High,
    Obfuscated,
    Neutral,
    Offline,
}

#[derive(Clone)]
struct DomainIntel {
    name: String,
    risk: RiskLevel,
    lat: f64,
    lon: f64,
    ips: Vec<String>,
    details: String,
    safemode_alerts: Vec<String>,
    tag: DomainTag,
}

#[derive(Deserialize)]
struct CorrelationReport {
    clusters: Vec<CorrelationCluster>,
    analyzed_domains: Vec<String>,
}

#[derive(Deserialize, Clone)]
struct CorrelationCluster {
    cluster_id: usize,
    correlation_type: String,
    shared_indicator: String,
    domains: Vec<String>,
    confidence: String,
    risk_assessment: String,
}

fn load_and_geolocate_domains(file_path: &str, reader: &Reader<Vec<u8>>) -> Vec<DomainIntel> {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let report: CorrelationReport = match serde_json::from_str(&content) {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let mut domain_map: HashMap<String, DomainIntel> = HashMap::new();
    for cluster in &report.clusters {
        for domain_name in &cluster.domains {
            let entry = domain_map
                .entry(domain_name.clone())
                .or_insert_with(|| DomainIntel {
                    name: domain_name.clone(),
                    risk: RiskLevel::Obfuscated,
                    lat: 0.0,
                    lon: 0.0,
                    ips: vec![],
                    details: String::new(),
                    safemode_alerts: vec![],
                    tag: DomainTag::None,
                });
            entry.details.push_str(&format!(
                "Cluster {}: {} (Shared: {})\nConfidence: {}\nAssessment: {}\n\n",
                cluster.cluster_id,
                cluster.correlation_type,
                cluster.shared_indicator,
                cluster.confidence,
                cluster.risk_assessment
            ));
            if cluster.correlation_type == "SHARED_CERTIFICATE" {
                entry.risk = RiskLevel::High;
            }
        }
    }
    for domain_name in &report.analyzed_domains {
        if !domain_map.contains_key(domain_name) {
            domain_map.insert(
                domain_name.clone(),
                DomainIntel {
                    name: domain_name.clone(),
                    risk: RiskLevel::Neutral,
                    lat: 0.0,
                    lon: 0.0,
                    ips: vec!["No correlations found".into()],
                    details: "Domain was analyzed but did not share infrastructure.".into(),
                    safemode_alerts: vec![],
                    tag: DomainTag::None,
                },
            );
        }
    }

    let mut domains: Vec<DomainIntel> = domain_map.into_values().collect();

    // NEW: Geolocate and ensure we actually have an IP to look up
    for domain in &mut domains {
        // 1. If the JSON didn't provide an IP, try to resolve the domain name to one
        if domain.ips.is_empty() || domain.ips[0] == "No correlations found" {
            if let Ok(mut addrs) = format!("{}:80", domain.name).to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    domain.ips = vec![addr.ip().to_string()];
                }
            }
        }

        // 2. Now geolocate the IP we have
        if let Some(first_ip) = domain.ips.first() {
            if let Ok(ip_addr) = first_ip.parse::<std::net::IpAddr>() {
                if let Ok(city_data) = reader.lookup::<City>(ip_addr) {
                    let loc = city_data.location.as_ref();
                    domain.lat = loc.and_then(|l| l.latitude).unwrap_or(0.0);
                    domain.lon = loc.and_then(|l| l.longitude).unwrap_or(0.0);
                }
            }
        }
    }
    domains
}

fn main() -> Result<(), std::io::Error> {
    println!("[*] Initializing Dullahan Unified Tactical Daemon...");

    let args: Vec<String> = env::args().collect();
    let input_file = if args.len() >= 3 && args[1] == "--input" {
        args[2].clone()
    } else {
        "infra_correlation_report.json".to_string()
    };

    let mmdb_bytes = include_bytes!("../assets/GeoLite2-City.mmdb").to_vec();
    let reader = Reader::from_source(mmdb_bytes).expect("Failed to load MaxMind DB");

    let domains_intel = load_and_geolocate_domains(&input_file, &reader);

    let web_domains: Vec<web_server::WebDomain> = domains_intel
        .into_iter()
        .map(|d| {
            let mut city = "Unknown".to_string();
            let mut country = "Unknown".to_string();
            let mut market_type = "Standard Infrastructure".to_string();

            if let Some(first_ip) = d.ips.first() {
                // Market Type Heuristic
                if first_ip.starts_with("104.")
                    || first_ip.starts_with("172.")
                    || first_ip.starts_with("173.")
                {
                    market_type = "CDN Proxy (e.g., Cloudflare)".to_string();
                } else if first_ip.starts_with("3.")
                    || first_ip.starts_with("52.")
                    || first_ip.starts_with("54.")
                {
                    market_type = "Enterprise Cloud (e.g., AWS)".to_string();
                }

                if let Ok(ip_addr) = first_ip.parse::<std::net::IpAddr>() {
                    if let Ok(city_data) = reader.lookup::<City>(ip_addr) {
                        city = city_data
                            .city
                            .and_then(|c| c.names)
                            .and_then(|n| n.get("en").map(|s| s.to_string()))
                            .unwrap_or_else(|| "Unknown".to_string());
                        country = city_data
                            .country
                            .and_then(|c| c.names)
                            .and_then(|n| n.get("en").map(|s| s.to_string()))
                            .unwrap_or_else(|| "Unknown".to_string());
                    }
                }
            }

            web_server::WebDomain {
                name: d.name,
                risk: match d.risk {
                    RiskLevel::High => "High".to_string(),
                    RiskLevel::Obfuscated => "Obfuscated".to_string(),
                    RiskLevel::Neutral => "Neutral".to_string(),
                    RiskLevel::Offline => "Offline".to_string(),
                },
                lat: d.lat,
                lon: d.lon,
                ips: d.ips,
                city,
                country,
                cert: "Embedded".to_string(),
                market_type,
                safemode_alerts: d.safemode_alerts,
                tag: match d.tag {
                    DomainTag::Safe => "Safe".to_string(),
                    DomainTag::Malicious => "Malicious".to_string(),
                    DomainTag::Investigate => "Investigate".to_string(),
                    DomainTag::None => "None".to_string(),
                },
            }
        })
        .collect();

    let initial_state = web_server::AppState {
        domains: web_domains,
        safemode_active: true,
        verification_status: "UNVERIFIED".to_string(),
    };

    let state = Arc::new(Mutex::new(initial_state));
    let server_state = Arc::clone(&state);

    thread::spawn(move || {
        web_server::start_web_server(server_state, 8080);
    });

    // Background Network Hijack Monitor
    let monitor_state = Arc::clone(&state);
    thread::spawn(move || {
        let mut last_hash = String::new();
        loop {
            if let Ok(contents) = fs::read_to_string("/etc/resolv.conf") {
                let mut hasher = DefaultHasher::new();
                contents.hash(&mut hasher);
                let current_hash = hasher.finish().to_string();

                if !last_hash.is_empty() && current_hash != last_hash {
                    let mut state = monitor_state.lock().unwrap();
                    state.verification_status = "⚠️ DNS ALTERATION DETECTED".to_string();
                    println!("[!] CRITICAL ALERT: /etc/resolv.conf was modified locally!");
                }
                last_hash = current_hash;
            }
            thread::sleep(std::time::Duration::from_secs(10));
        }
    });

    println!("[+] Daemon running at http://127.0.0.1:8080");
    println!("[*] Open your browser to view the tactical map interface.");
    println!("[*] Press Ctrl+C to stop the daemon.");

    loop {
        thread::sleep(std::time::Duration::from_secs(3600));
    }
}
