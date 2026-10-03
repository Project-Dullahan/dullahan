use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use url::Url;

#[derive(Deserialize)]
struct HarFile {
    log: HarLog,
}

#[derive(Deserialize)]
struct HarLog {
    entries: Vec<HarEntry>,
}

#[derive(Deserialize)]
struct HarEntry {
    request: HarRequest,
    response: HarResponse,
}

#[derive(Deserialize)]
struct HarRequest {
    #[serde(default)]
    method: String,
    url: String,
}

#[derive(Deserialize)]
struct HarResponse {
    #[serde(default)]
    content: HarContent,
}

#[derive(Deserialize, Default)]
struct HarContent {
    #[serde(default)]
    size: u64,
}

fn extract_domain(url: &str) -> Option<String> {
    Url::parse(url).ok()?.host_str().map(|h| h.to_string())
}

fn is_fingerprinting_attempt(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("fingerprint")
        || lower.contains("canvas")
        || lower.contains("webgl")
        || lower.contains("audiocontext")
        || lower.contains("navigator")
        || lower.contains("device-memory")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: har_analyzer <captured_traffic.har>");
        eprintln!(
            "Export a .har file from your browser's DevTools (Network tab -> Save all as HAR)"
        );
        std::process::exit(1);
    }

    let file_path = &args[1];
    println!("[DULLAHAN] Initiating passive behavioral traffic analysis...");
    println!("Reading HAR file: {}\n", file_path);

    let file_content = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error: Could not read HAR file. ({})", e);
            std::process::exit(1);
        }
    };

    let har: HarFile = match serde_json::from_str(&file_content) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error: Invalid HAR file format. ({})", e);
            std::process::exit(1);
        }
    };

    println!("[INFO] Parsed {} HTTP entries.", har.log.entries.len());

    let mut domain_stats: HashMap<String, (u64, usize, usize)> = HashMap::new(); // (bytes, requests, post_requests)
    let mut fingerprinting_domains: HashSet<String> = HashSet::new();
    let mut total_bytes: u64 = 0;

    for entry in &har.log.entries {
        if let Some(domain) = extract_domain(&entry.request.url) {
            let stats = domain_stats.entry(domain.clone()).or_insert((0, 0, 0));
            stats.0 += entry.response.content.size;
            stats.1 += 1;
            if entry.request.method.to_uppercase() == "POST" {
                stats.2 += 1;
            }
            total_bytes += entry.response.content.size;

            if is_fingerprinting_attempt(&entry.request.url) {
                fingerprinting_domains.insert(domain);
            }
        }
    }

    println!("\n=== PASSIVE BEHAVIORAL ANALYSIS ===");
    println!("Unique domains contacted: {}", domain_stats.len());
    println!("Total data transferred: {} KB\n", total_bytes / 1024);

    // Behavioral Flag 1: Tracker Density
    if domain_stats.len() > 15 {
        println!(
            "[WARNING] HIGH TRACKER DENSITY: Page contacted {} unique domains.",
            domain_stats.len()
        );
        println!(
            "          This is unusually high and suggests aggressive third-party tracking.\n"
        );
    }

    // Behavioral Flag 2: Fingerprinting
    if !fingerprinting_domains.is_empty() {
        println!("[WARNING] FINGERPRINTING DETECTED: The following domains attempted to gather browser/device fingerprints:");
        for domain in &fingerprinting_domains {
            println!("  - {}", domain);
        }
        println!();
    }

    println!("Top Domains by Data Volume & Behavior:");
    let mut sorted_domains: Vec<_> = domain_stats.iter().collect();
    sorted_domains.sort_by_key(|(_, stats)| std::cmp::Reverse(stats.0));

    for (domain, (bytes, requests, posts)) in sorted_domains.iter().take(15) {
        let mut flags = Vec::new();
        if *posts > 0 {
            flags.push(format!("{} POSTs", posts));
        }
        if fingerprinting_domains.contains(*domain) {
            flags.push("FINGERPRINTING".to_string());
        }

        let flag_str = if flags.is_empty() {
            "".to_string()
        } else {
            format!(" [{}]", flags.join(", "))
        };

        println!(
            "  [{:>6} KB] [{:>3} req] {}{}",
            bytes / 1024,
            requests,
            domain,
            flag_str
        );
    }

    // Output domains to a file for batch processing by cname_unmask
    let output_path = "har_extracted_domains.txt";
    let domains_list: Vec<String> = domain_stats.keys().cloned().collect();
    match fs::write(output_path, domains_list.join("\n")) {
        Ok(_) => {
            println!(
                "\n[SUCCESS] Extracted {} unique domains to: {}",
                domain_stats.len(),
                output_path
            );
            println!(
                "[INFO] Next step: ./target/release/cname_unmask {}",
                output_path
            );
        }
        Err(e) => eprintln!("Error: Could not write extracted domains. ({})", e),
    }
}
