mod forensics;
mod geo;
mod scanner;
mod web_server;

use maxminddb::Reader;
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::thread;
use web_server::WebDomain;

#[derive(Deserialize)]
struct CorrelationReport {
    clusters: Vec<CorrelationCluster>,
    analyzed_domains: Vec<String>,
    #[serde(default)]
    threat_ips: Vec<ThreatIp>,
}

/// An IP indicator imported from an external feed. `source` should name the feed;
/// entries without one are shown in the UI as unverified.
#[derive(Deserialize)]
struct ThreatIp {
    ip: String,
    risk: String,
    label: String,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Deserialize)]
struct CorrelationCluster {
    cluster_id: usize,
    correlation_type: String,
    shared_indicator: String,
    domains: Vec<String>,
    confidence: String,
    risk_assessment: String,
}

fn new_domain(name: &str, risk: &str) -> WebDomain {
    WebDomain {
        name: name.to_string(),
        risk: risk.to_string(),
        lat: 0.0,
        lon: 0.0,
        ips: vec![],
        city: "Unknown".to_string(),
        country: "Unknown".to_string(),
        cert: "Embedded".to_string(),
        market_type: "Standard Infrastructure".to_string(),
        details: String::new(),
        source: None,
        located: false,
        safemode_alerts: vec![],
        tag: "None".to_string(),
    }
}

fn market_type(ip: &str) -> &'static str {
    if ip.starts_with("104.") || ip.starts_with("172.") || ip.starts_with("173.") {
        "CDN Proxy (e.g., Cloudflare)"
    } else if ip.starts_with("3.") || ip.starts_with("52.") || ip.starts_with("54.") {
        "Enterprise Cloud (e.g., AWS)"
    } else {
        "Standard Infrastructure"
    }
}

fn load_and_geolocate_domains(file_path: &str, reader: &Reader<Vec<u8>>) -> Vec<WebDomain> {
    let report: CorrelationReport = match fs::read_to_string(file_path)
        .map_err(|e| e.to_string())
        .and_then(|c| serde_json::from_str(&c).map_err(|e| e.to_string()))
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "[!] Could not load correlation report '{}': {}",
                file_path, e
            );
            return vec![];
        }
    };

    let mut domain_map: HashMap<String, WebDomain> = HashMap::new();
    for cluster in &report.clusters {
        for domain_name in &cluster.domains {
            let entry = domain_map
                .entry(domain_name.clone())
                .or_insert_with(|| new_domain(domain_name, "Obfuscated"));
            entry.details.push_str(&format!(
                "Cluster {}: {} (Shared: {})\nConfidence: {}\nAssessment: {}\n\n",
                cluster.cluster_id,
                cluster.correlation_type,
                cluster.shared_indicator,
                cluster.confidence,
                cluster.risk_assessment
            ));
            if cluster.correlation_type == "SHARED_CERTIFICATE" {
                entry.risk = "High".to_string();
            }
        }
    }
    for domain_name in &report.analyzed_domains {
        domain_map.entry(domain_name.clone()).or_insert_with(|| {
            let mut d = new_domain(domain_name, "Neutral");
            d.details = "Domain was analyzed but did not share infrastructure.".to_string();
            d
        });
    }

    let mut domains: Vec<WebDomain> = domain_map.into_values().collect();

    for domain in &mut domains {
        if let Ok(addrs) = format!("{}:80", domain.name).to_socket_addrs() {
            // IPv4 first: GeoLite2 has far better coordinate coverage for v4 than v6
            let mut ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            ips.sort_by_key(|ip| ip.contains(':'));
            ips.dedup();
            domain.ips = ips;
        }
        geolocate(domain, reader);
    }

    for threat in report.threat_ips {
        let risk = match threat.risk.to_lowercase().as_str() {
            "high" => "High",
            "medium" => "Obfuscated",
            _ => "Neutral",
        };
        let mut d = new_domain(&threat.label, risk);
        d.details = format!(
            "Threat indicator: {} ({})\nSource: {}",
            threat.label,
            threat.ip,
            threat
                .source
                .as_deref()
                .unwrap_or("UNVERIFIED - no source given")
        );
        d.source = Some(threat.source.unwrap_or_else(|| "unverified".to_string()));
        d.ips = vec![threat.ip];
        geolocate(&mut d, reader);
        domains.push(d);
    }

    domains
}

/// Fills location fields from the first IP that GeoLite2 can place on the map.
fn geolocate(domain: &mut WebDomain, reader: &Reader<Vec<u8>>) {
    if let Some(first_ip) = domain.ips.first() {
        domain.market_type = market_type(first_ip).to_string();
    }
    for ip in &domain.ips {
        if let Some(info) = geo::lookup(reader, ip) {
            if let (Some(lat), Some(lon)) = (info.lat, info.lon) {
                domain.lat = lat;
                domain.lon = lon;
                domain.city = info.city;
                domain.country = info.country;
                domain.located = true;
                return;
            }
        }
    }
}

fn main() {
    println!("[*] Initializing Dullahan Unified Tactical Daemon...");

    let args: Vec<String> = env::args().collect();
    let input_file = if args.len() >= 3 && args[1] == "--input" {
        args[2].clone()
    } else {
        "infra_correlation_report.json".to_string()
    };

    let mmdb_bytes = include_bytes!("../assets/GeoLite2-City.mmdb").to_vec();
    let reader = Reader::from_source(mmdb_bytes).expect("Failed to load MaxMind DB");

    let initial_state = web_server::AppState {
        domains: load_and_geolocate_domains(&input_file, &reader),
        safemode_active: true,
        verification_status: "UNVERIFIED".to_string(),
        dns_tampered: false,
        last_file_scan_flags: None,
        last_history_dbs: None,
    };
    let state = Arc::new(Mutex::new(initial_state));

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
                    state.dns_tampered = true;
                    println!("[!] CRITICAL ALERT: /etc/resolv.conf was modified locally!");
                }
                last_hash = current_hash;
            }
            thread::sleep(std::time::Duration::from_secs(10));
        }
    });

    // Blocks for the lifetime of the daemon; only returns if the server fails to start.
    if let Err(e) = web_server::start_web_server(state, 8080) {
        eprintln!("[-] Failed to start server on port 8080: {}", e);
        std::process::exit(1);
    }
}
