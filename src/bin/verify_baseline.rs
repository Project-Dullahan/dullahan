// src/bin/verify_baseline.rs

use ring::digest::{digest, SHA256};
use rustls::{ClientConfig, RootCertStore, ServerName};
use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Deserialize, Debug)]
struct BaselineConfig {
    generated_at: String,
    trusted_profiles: std::collections::HashMap<String, DomainProfile>,
}

#[derive(Deserialize, Debug, Clone)]
struct DomainProfile {
    domain: String,
    expected_cert_sha256: String,
    resolved_infrastructure: Vec<IpProfile>,
}

#[derive(Deserialize, Debug, Clone)]
struct IpProfile {
    ip: String,
    asn: String,
    asn_organization: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin verify_baseline -- <domain>");
        std::process::exit(1);
    }
    let target_domain = &args[1];

    let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("dullahan");
    let manifest_path = config_dir.join("baseline.json");
    
    if !manifest_path.exists() {
        eprintln!("[!] CRITICAL: Manifest file missing at {:?}", manifest_path);
        std::process::exit(1);
    }

    let file = File::open(&manifest_path)?;
    let reader = BufReader::new(file);
    let baseline: BaselineConfig = serde_json::from_reader(reader)?;

    let profile = match baseline.trusted_profiles.get(target_domain) {
        Some(p) => p.clone(),
        None => {
            eprintln!("[!] ERROR: Domain '{}' not found in trusted_profiles.", target_domain);
            std::process::exit(1);
        }
    };

    println!("[*] Commencing verification for: {}", profile.domain);

    // 1. Perform live DNS resolution
    let socket_addr_str = format!("{}:443", profile.domain);
    let live_ips: HashSet<String> = match socket_addr_str.to_socket_addrs() {
        Ok(addrs) => addrs.map(|addr| addr.ip().to_string()).collect(),
        Err(e) => {
            eprintln!("[!] FAIL-SECURE: Could not resolve domain: {}", e);
            std::process::exit(2);
        }
    };

    let expected_ips: HashSet<String> = profile.resolved_infrastructure.iter().map(|ip| ip.ip.clone()).collect();
    let mutated_ips: Vec<&String> = live_ips.difference(&expected_ips).collect();
    
    let mut ip_warning = false;
    if !mutated_ips.is_empty() {
        println!("[⚠️] WARNING: DNS Shift Detected (New IPs resolved)");
        for ip in &mutated_ips {
            println!("  ↳ Unverified IP: {}", ip);
        }
        println!("[*] Proceeding to cryptographic verification to determine if this is a safe CDN rotation or a hijack...");
        ip_warning = true;
    } else {
        println!("[+] DNS Verification: PASS (All resolved IPs match trusted baseline)");
    }

    // 2. Verify TLS Certificate Pinning
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
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

    let server_name = ServerName::try_from(profile.domain.as_str())
        .map_err(|_| "Invalid DNS name")?;
        
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut sock = TcpStream::connect(&socket_addr_str)?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    if let Err(e) = tls.flush() {
        eprintln!("[!] FAIL-SECURE: TLS Handshake failed: {}", e);
        std::process::exit(4);
    }

    if let Some(certs) = conn.peer_certificates() {
        if let Some(leaf_cert) = certs.first() {
            let actual_hash = digest(&SHA256, leaf_cert.as_ref());
            let actual_hash_hex = hex::encode(actual_hash);

            if actual_hash_hex.to_lowercase() != profile.expected_cert_sha256.to_lowercase() {
                println!("[!!!] CRITICAL ALERT: TLS CERTIFICATE MITM DETECTED [!!!]");
                println!("  Expected Hash: {}", profile.expected_cert_sha256);
                println!("  Received Hash: {}", actual_hash_hex);
                std::process::exit(5);
            } else {
                println!("[+] TLS Pinning Verification: PASS (Certificate matches pre-vetted hash)");
                if ip_warning {
                    println!("[✅] VERIFICATION COMPLETE: IP shifted, but cryptographic identity is verified. Likely safe CDN rotation.");
                } else {
                    println!("[✅] VERIFICATION COMPLETE: Connection is fully secure based on trusted baseline.");
                }
            }
        } else {
            eprintln!("[!] FAIL-SECURE: No certificates presented by server.");
            std::process::exit(6);
        }
    } else {
        eprintln!("[!] FAIL-SECURE: Peer certificate chain is unavailable.");
        std::process::exit(7);
    }

    Ok(())
}
