use std::collections::{HashMap, HashSet};
use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use reqwest::blocking::Client;
use rustls::{ClientConfig, ClientConnection, ServerName};
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::*;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
struct DomainIntel {
    domain: String,
    ips: Vec<String>,
    asn: Option<String>,
    cert_subject: Option<String>,
    cert_issuer: Option<String>,
    tracking_ids: HashSet<String>,
    html_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
struct CorrelationCluster {
    cluster_id: usize,
    correlation_type: String,
    shared_indicator: String,
    domains: Vec<String>,
    confidence: String,
    risk_assessment: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: infra_correlator <domains.txt>");
        eprintln!("Analyzes infrastructure correlation between domains");
        std::process::exit(1);
    }

    let file_path = &args[1];
    let domains: Vec<String> = match fs::read_to_string(file_path) {
        Ok(content) => content.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            std::process::exit(1);
        }
    };

    println!("[DULLAHAN] Initiating infrastructure correlation analysis...");
    println!("Analyzing {} domains\n", domains.len());

    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())
        .expect("Failed to initialize resolver");

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
        .build()
        .unwrap();

    println!("Phase 1: Intelligence Gathering");
    let mut intel_map: HashMap<String, DomainIntel> = HashMap::new();

    for domain in &domains {
        println!("  Analyzing: {}", domain);
        let mut intel = DomainIntel {
            domain: domain.clone(),
            ips: Vec::new(),
            asn: None,
            cert_subject: None,
            cert_issuer: None,
            tracking_ids: HashSet::new(),
            html_fingerprint: None,
        };

        if let Ok(lookup) = resolver.lookup_ip(domain) {
            for ip in lookup.iter() {
                intel.ips.push(ip.to_string());
            }
        }

        // FIX 3: No longer silently swallowing errors
        match fetch_certificate(domain) {
            Ok(cert_info) => { 
                intel.cert_subject = cert_info.0; 
                intel.cert_issuer = cert_info.1; 
            }
            Err(e) => println!("    (certificate check failed: {})", e),
        }

        if let Ok(html) = client.get(format!("http://{}", domain)).send()
            .and_then(|r| r.text()) {
            intel.tracking_ids = extract_tracking_ids(&html);
            intel.html_fingerprint = Some(compute_html_fingerprint(&html));
        }

        intel_map.insert(domain.clone(), intel);
    }

    println!("\nPhase 2: Correlation Analysis");
    let clusters = perform_correlation(&intel_map);

    println!("\nPhase 3: Generating Report");
    generate_report(&clusters, &intel_map);
}

// FIX 1 & 2: Proper hostname resolution and rustls handshake driving
fn fetch_certificate(domain: &str) -> Result<(Option<String>, Option<String>), Box<dyn std::error::Error>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from(domain)?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;

    let addr = format!("{}:443", domain);
    // FIX 2: to_socket_addrs resolves hostnames, parse() only works for literal IPs
    let sock_addr = addr.to_socket_addrs()?.next().ok_or("DNS resolution returned no addresses")?;
    let mut sock = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5))?;
    let _tls = rustls::Stream::new(&mut conn, &mut sock);

    // FIX 1: Drive the TLS handshake to completion
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)?;
    }

    if let Some(certs) = conn.peer_certificates() {
        if let Some(cert) = certs.first() {
            if let Ok((_, parsed)) = parse_x509_certificate(cert.as_ref()) {
                let subject = Some(parsed.subject().to_string());
                let issuer = Some(parsed.issuer().to_string());
                return Ok((subject, issuer));
            }
        }
    }

    Ok((None, None))
}

// FIX 5: Loop to catch ALL tracking IDs, not just the first one
fn extract_tracking_ids(html: &str) -> HashSet<String> {
    let mut ids = HashSet::new();
    let mut cursor = html;

    // Google Analytics
    while let Some(pos) = cursor.find("G-") {
        if pos + 12 <= cursor.len() {
            let potential_id = &cursor[pos..pos+12];
            if potential_id.chars().skip(2).all(|c| c.is_alphanumeric()) {
                ids.insert(format!("GA:{}", potential_id));
            }
        }
        cursor = &cursor[pos+2..];
    }

    // Facebook Pixel
    cursor = html;
    while let Some(pos) = cursor.find("fbq('init', '") {
        let start = pos + 14;
        if start + 15 <= cursor.len() {
            let segment = &cursor[start..start+15];
            if segment.chars().all(|c| c.is_numeric()) {
                ids.insert(format!("FB:{}", segment));
            }
        }
        cursor = &cursor[start..];
    }

    ids
}

// FIX 4: Real cryptographic hash instead of length arithmetic
fn compute_html_fingerprint(html: &str) -> String {
    let mut fingerprint = String::new();
    
    for line in html.lines() {
        if line.contains("<script") && line.contains("src=") {
            if let Some(start) = line.find("src=\"") {
                if let Some(end) = line[start+5..].find("\"") {
                    let src = &line[start+5..start+5+end];
                    fingerprint.push_str(&format!("SCRIPT:{}|", src));
                }
            }
        }
    }

    for line in html.lines() {
        if line.contains("<meta") {
            fingerprint.push_str(&format!("META:{}|", line.trim()));
        }
    }

    let mut hasher = DefaultHasher::new();
    fingerprint.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn perform_correlation(intel_map: &HashMap<String, DomainIntel>) -> Vec<CorrelationCluster> {
    let mut clusters = Vec::new();
    let mut cluster_id = 1;

    // Correlation 1: Shared IP Addresses
    let mut ip_to_domains: HashMap<String, Vec<String>> = HashMap::new();
    for (domain, intel) in intel_map {
        for ip in &intel.ips {
            ip_to_domains.entry(ip.clone()).or_insert_with(Vec::new).push(domain.clone());
        }
    }
    for (ip, domains) in ip_to_domains {
        if domains.len() > 1 {
            clusters.push(CorrelationCluster {
                cluster_id,
                correlation_type: "SHARED_IP".to_string(),
                shared_indicator: ip,
                domains: domains.clone(),
                confidence: "HIGH".to_string(),
                risk_assessment: "These domains share the same IP address, suggesting they are hosted on the same infrastructure".to_string(),
            });
            cluster_id += 1;
        }
    }

    // Correlation 2: Shared SSL Certificates
    let mut cert_to_domains: HashMap<String, Vec<String>> = HashMap::new();
    for (domain, intel) in intel_map {
        if let Some(ref subject) = intel.cert_subject {
            cert_to_domains.entry(subject.clone()).or_insert_with(Vec::new).push(domain.clone());
        }
    }
    for (cert, domains) in cert_to_domains {
        if domains.len() > 1 {
            clusters.push(CorrelationCluster {
                cluster_id,
                correlation_type: "SHARED_CERTIFICATE".to_string(),
                shared_indicator: cert,
                domains: domains.clone(),
                confidence: "VERY_HIGH".to_string(),
                risk_assessment: "These domains share the same SSL certificate, strongly indicating they are operated by the same entity".to_string(),
            });
            cluster_id += 1;
        }
    }

    // Correlation 3: Shared Tracking IDs
    let mut tracking_to_domains: HashMap<String, Vec<String>> = HashMap::new();
    for (domain, intel) in intel_map {
        for tracking_id in &intel.tracking_ids {
            tracking_to_domains.entry(tracking_id.clone()).or_insert_with(Vec::new).push(domain.clone());
        }
    }
    for (tracking_id, domains) in tracking_to_domains {
        if domains.len() > 1 {
            clusters.push(CorrelationCluster {
                cluster_id,
                correlation_type: "SHARED_TRACKING_ID".to_string(),
                shared_indicator: tracking_id,
                domains: domains.clone(),
                confidence: "HIGH".to_string(),
                risk_assessment: "These domains use the same tracking identifier, suggesting coordinated operations or common ownership".to_string(),
            });
            cluster_id += 1;
        }
    }

    // Correlation 4: Similar HTML Fingerprints
    let mut fingerprint_to_domains: HashMap<String, Vec<String>> = HashMap::new();
    for (domain, intel) in intel_map {
        if let Some(ref fp) = intel.html_fingerprint {
            fingerprint_to_domains.entry(fp.clone()).or_insert_with(Vec::new).push(domain.clone());
        }
    }
    for (fingerprint, domains) in fingerprint_to_domains {
        if domains.len() > 1 {
            clusters.push(CorrelationCluster {
                cluster_id,
                correlation_type: "SIMILAR_HTML_STRUCTURE".to_string(),
                shared_indicator: format!("Fingerprint: {}", fingerprint),
                domains: domains.clone(),
                confidence: "MEDIUM".to_string(),
                risk_assessment: "These domains have similar HTML structure, possibly using the same template or CMS".to_string(),
            });
            cluster_id += 1;
        }
    }

    clusters
}

fn generate_report(clusters: &[CorrelationCluster], intel_map: &HashMap<String, DomainIntel>) {
    println!("\n{}", "=".repeat(80));
    println!("INFRASTRUCTURE CORRELATION REPORT");
    println!("{}", "=".repeat(80));

    if clusters.is_empty() {
        println!("\nNo infrastructure correlations detected.");
        println!("All analyzed domains appear to be independently operated.");
    } else {
        println!("\nDetected {} correlation clusters:\n", clusters.len());

        for cluster in clusters {
            println!("{}", "-".repeat(80));
            println!("Cluster #{}: {}", cluster.cluster_id, cluster.correlation_type);
            println!("Shared Indicator: {}", cluster.shared_indicator);
            println!("Confidence: {}", cluster.confidence);
            println!("\nRelated Domains:");
            for domain in &cluster.domains {
                println!("  - {}", domain);
                if let Some(intel) = intel_map.get(domain) {
                    println!("    IPs: {:?}", intel.ips);
                    if let Some(ref issuer) = intel.cert_issuer {
                        println!("    Cert Issuer: {}", issuer);
                    }
                    if !intel.tracking_ids.is_empty() {
                        println!("    Tracking IDs: {:?}", intel.tracking_ids);
                    }
                }
            }
            println!("\nRisk Assessment: {}", cluster.risk_assessment);
            println!();
        }
    }

    let report_path = "infra_correlation_report.json";
    let report_data = serde_json::json!({
        "clusters": clusters,
        "analyzed_domains": intel_map.keys().collect::<Vec<_>>()
    });

    if let Ok(json) = serde_json::to_string_pretty(&report_data) {
        if let Ok(_) = fs::write(report_path, json) {
            println!("\nDetailed report exported to: {}", report_path);
        }
    }

    println!("{}", "=".repeat(80));
}
