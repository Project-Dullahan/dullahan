use reqwest::blocking::Client;
use rustls::{ClientConfig, ClientConnection, ServerName};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::*;

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
        Ok(content) => content
            .lines()
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

        if let Ok(html) = client
            .get(format!("http://{}", domain))
            .send()
            .and_then(|r| r.text())
        {
            intel.tracking_ids = extract_tracking_ids(&html);
            intel.html_fingerprint = compute_html_fingerprint(&html);
        }

        intel_map.insert(domain.clone(), intel);
    }

    println!("\nPhase 2: Correlation Analysis");
    let clusters = perform_correlation(&intel_map);

    println!("\nPhase 3: Generating Report");
    generate_report(&clusters, &intel_map);
}

// FIX 1 & 2: Proper hostname resolution and rustls handshake driving
fn fetch_certificate(
    domain: &str,
) -> Result<(Option<String>, Option<String>), Box<dyn std::error::Error>> {
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
    let sock_addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or("DNS resolution returned no addresses")?;
    let mut sock = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5))?;

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

// Collect ALL tracking IDs, not just the first one
fn extract_tracking_ids(html: &str) -> HashSet<String> {
    let mut ids = HashSet::new();

    // Google Analytics 4: "G-" followed by 10 alphanumerics.
    // `get` (not indexing) so a multi-byte UTF-8 char at the boundary can't panic.
    for (pos, _) in html.match_indices("G-") {
        if let Some(potential_id) = html.get(pos..pos + 12) {
            if potential_id[2..].chars().all(|c| c.is_ascii_alphanumeric()) {
                ids.insert(format!("GA:{}", potential_id));
            }
        }
    }

    // Facebook Pixel: fbq('init', '<15-16 digit id>')
    const FB_PREFIX: &str = "fbq('init', '";
    for (pos, _) in html.match_indices(FB_PREFIX) {
        let digits: String = html[pos + FB_PREFIX.len()..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if digits.len() >= 15 {
            ids.insert(format!("FB:{}", digits));
        }
    }

    ids
}

// SHA-256 so fingerprints are stable across runs and toolchains
/// Returns None when the page has no script/meta structure to fingerprint; otherwise every
/// such page would hash identically and be falsely clustered together.
fn compute_html_fingerprint(html: &str) -> Option<String> {
    let mut fingerprint = String::new();

    for line in html.lines() {
        if line.contains("<script") && line.contains("src=") {
            if let Some(start) = line.find("src=\"") {
                if let Some(end) = line[start + 5..].find("\"") {
                    let src = &line[start + 5..start + 5 + end];
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

    if fingerprint.is_empty() {
        return None;
    }

    Some(hex::encode(ring::digest::digest(
        &ring::digest::SHA256,
        fingerprint.as_bytes(),
    )))
}

/// Groups domains by `indicators` and emits a cluster for each indicator shared by 2+ domains.
fn push_clusters<F, I>(
    clusters: &mut Vec<CorrelationCluster>,
    intel_map: &HashMap<String, DomainIntel>,
    correlation_type: &str,
    confidence: &str,
    risk_assessment: &str,
    indicators: F,
) where
    F: Fn(&DomainIntel) -> I,
    I: IntoIterator<Item = String>,
{
    // BTreeMap so cluster ordering/IDs are stable between runs
    let mut by_indicator: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (domain, intel) in intel_map {
        for indicator in indicators(intel) {
            by_indicator
                .entry(indicator)
                .or_default()
                .push(domain.clone());
        }
    }
    for (shared_indicator, mut domains) in by_indicator {
        domains.sort();
        domains.dedup();
        if domains.len() > 1 {
            clusters.push(CorrelationCluster {
                cluster_id: clusters.len() + 1,
                correlation_type: correlation_type.to_string(),
                shared_indicator,
                domains,
                confidence: confidence.to_string(),
                risk_assessment: risk_assessment.to_string(),
            });
        }
    }
}

fn perform_correlation(intel_map: &HashMap<String, DomainIntel>) -> Vec<CorrelationCluster> {
    let mut clusters = Vec::new();

    push_clusters(&mut clusters, intel_map, "SHARED_IP", "HIGH",
        "These domains share the same IP address, suggesting they are hosted on the same infrastructure",
        |i| i.ips.clone());
    push_clusters(&mut clusters, intel_map, "SHARED_CERTIFICATE", "VERY_HIGH",
        "These domains share the same SSL certificate, strongly indicating they are operated by the same entity",
        |i| i.cert_subject.clone());
    push_clusters(&mut clusters, intel_map, "SHARED_TRACKING_ID", "HIGH",
        "These domains use the same tracking identifier, suggesting coordinated operations or common ownership",
        |i| i.tracking_ids.iter().cloned().collect::<Vec<_>>());
    push_clusters(
        &mut clusters,
        intel_map,
        "SIMILAR_HTML_STRUCTURE",
        "MEDIUM",
        "These domains have similar HTML structure, possibly using the same template or CMS",
        |i| {
            i.html_fingerprint
                .as_ref()
                .map(|fp| format!("Fingerprint: {}", fp))
        },
    );

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
            println!(
                "Cluster #{}: {}",
                cluster.cluster_id, cluster.correlation_type
            );
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
    // threat_ips are imported by hand from external feeds; carry them over rather than wipe them
    let threat_ips = fs::read_to_string(report_path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|v| v.get("threat_ips").cloned())
        .unwrap_or_else(|| serde_json::json!([]));
    let mut analyzed_domains: Vec<_> = intel_map.keys().collect();
    analyzed_domains.sort();
    let report_data = serde_json::json!({
        "clusters": clusters,
        "analyzed_domains": analyzed_domains,
        "threat_ips": threat_ips
    });

    if let Ok(json) = serde_json::to_string_pretty(&report_data) {
        if fs::write(report_path, json).is_ok() {
            println!("\nDetailed report exported to: {}", report_path);
        }
    }

    println!("{}", "=".repeat(80));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_full_tracking_ids() {
        let html =
            "<script>gtag('config','G-ABCDE12345');fbq('init', '1234567890123456');</script>";
        let ids = extract_tracking_ids(html);
        assert!(ids.contains("GA:G-ABCDE12345"));
        assert!(ids.contains("FB:1234567890123456"));
    }

    #[test]
    fn pages_without_structure_are_not_fingerprinted() {
        assert_eq!(
            compute_html_fingerprint("<html><body>hi</body></html>"),
            None
        );
    }

    #[test]
    fn multibyte_text_near_ga_prefix_does_not_panic() {
        extract_tracking_ids("G-ABCDEFGHé€€€");
    }
}
