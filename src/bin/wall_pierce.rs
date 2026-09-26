use reqwest::blocking::Client;
use rustls::{ClientConfig, ClientConnection, ServerName, Stream};
use std::env;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use x509_parser::prelude::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: wall_pierce <url> (e.g., https://example.com)");
        std::process::exit(1);
    }

    let target = &args[1];
    let parsed_url = match Url::parse(target) {
        Ok(u) => u,
        Err(_) => {
            eprintln!("Error: Invalid URL provided. Ensure it starts with http:// or https://");
            std::process::exit(1);
        }
    };

    println!("[DULLAHAN] Initiating transport security and header audit...");
    println!("Target: {}\n", target);

    let scheme = parsed_url.scheme();
    let host = parsed_url.host_str().unwrap_or("unknown");
    let port = parsed_url
        .port()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    // --- PHASE 1: TLS Certificate Audit (HTTPS only) ---
    if scheme == "https" {
        println!("--- PHASE 1: TLS Certificate Analysis ---");

        let mut root_store = rustls::RootCertStore::empty();
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

        let server_name = match ServerName::try_from(host) {
            Ok(name) => name,
            Err(_) => {
                println!("  [FAIL] Invalid hostname for TLS verification.");
                std::process::exit(1);
            }
        };

        let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();

        // Resolve address for connect_timeout
        let addr_str = format!("{}:{}", host, port);
        let sock_addr = match addr_str.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => {
                    println!("  [FAIL] Could not resolve host to an IP address.");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                println!("  [FAIL] DNS resolution failed. ({})", e);
                std::process::exit(1);
            }
        };

        match TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5)) {
            Ok(mut sock) => {
                let mut tls = Stream::new(&mut conn, &mut sock);
                // Trigger handshake by attempting to write
                let _ = tls.write_all(b"GET / HTTP/1.1\r\n\r\n");

                if let Some(certs) = conn.peer_certificates() {
                    if let Some(der_cert) = certs.first() {
                        match parse_x509_certificate(der_cert.as_ref()) {
                            Ok((_, cert)) => {
                                let subject = cert.subject().to_string();
                                let issuer = cert.issuer().to_string();
                                let validity = cert.validity();

                                println!("  [INFO] Subject: {}", subject);
                                println!("  [INFO] Issuer: {}", issuer);
                                println!("  [INFO] Valid From: {}", validity.not_before);
                                println!("  [INFO] Valid Until: {}", validity.not_after);

                                if issuer.to_lowercase().contains("self-signed")
                                    || issuer.len() < 20
                                {
                                    println!("  [WARNING] Certificate appears to be self-signed or from an untrusted local CA.");
                                }
                            }
                            Err(e) => {
                                println!("  [FAIL] Could not parse X.509 certificate. ({:?})", e)
                            }
                        }
                    }
                } else {
                    println!("  [FAIL] No peer certificate provided by server.");
                }
            }
            Err(e) => println!("  [FAIL] TCP connection to port {} failed. ({})", port, e),
        }
        println!();
    } else {
        println!("--- PHASE 1: TLS Certificate Analysis ---");
        println!(
            "  [WARNING] Target uses HTTP. Traffic is unencrypted and vulnerable to interception."
        );
        println!();
    }

    // --- PHASE 2: HTTP Security Header Audit ---
    println!("--- PHASE 2: HTTP Security Header Analysis ---");

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) Dullahan/0.1 Security Audit")
        .build()
        .expect("Failed to initialize HTTP client.");

    match client.get(target).send() {
        Ok(resp) => {
            let headers = resp.headers();
            let mut missing_count = 0;

            let checks = [
                (
                    "content-security-policy",
                    "Content-Security-Policy (CSP) - Prevents XSS/Injection",
                ),
                (
                    "strict-transport-security",
                    "Strict-Transport-Security (HSTS) - Enforces HTTPS",
                ),
                ("x-frame-options", "X-Frame-Options - Prevents Clickjacking"),
                (
                    "x-content-type-options",
                    "X-Content-Type-Options - Prevents MIME-sniffing",
                ),
            ];

            for (header_key, description) in checks {
                if headers.contains_key(header_key) {
                    println!("  [PASS] {} is present.", description);
                } else {
                    println!("  [FAIL] {} is MISSING.", description);
                    missing_count += 1;
                }
            }

            println!(
                "\n[SUMMARY] {} of 4 critical security headers are missing.",
                missing_count
            );
            if missing_count >= 3 {
                println!("[WARNING] Target has a severely degraded security posture.");
            }
        }
        Err(e) => eprintln!(
            "Error: Failed to connect to target for header audit. ({})",
            e
        ),
    }

    println!("\n[INFO] Audit complete.");
}
