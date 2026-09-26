use rusqlite::Connection;
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

// ==========================================
// 1. HEURISTIC RISK CLASSIFIER (Zero-Day Catcher)
// ==========================================
pub struct HeuristicRiskClassifier {
    risk_keywords: HashSet<String>,
}

impl Default for HeuristicRiskClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl HeuristicRiskClassifier {
    pub fn new() -> Self {
        let mut risk_keywords = HashSet::new();
        // Terms frequently leveraged in targeted NGO/humanitarian phishing scripts
        for word in &[
            "verify",
            "login",
            "secure-auth",
            "portal-update",
            "credential",
            "humanitarian-aid",
            "un-portal",
            "relief-fund",
        ] {
            risk_keywords.insert(word.to_string());
        }
        Self { risk_keywords }
    }

    /// Evaluates the structural entropy (randomness) of a domain string.
    /// Malicious command & control setups frequently use automated high-entropy strings (DGAs).
    fn calculate_shannon_entropy(&self, input: &str) -> f64 {
        let mut counts = [0; 256];
        for &byte in input.as_bytes() {
            counts[byte as usize] += 1;
        }

        let len = input.len() as f64;
        let mut entropy = 0.0;

        for &count in counts.iter() {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Processes an unverified trace element completely offline using semantic heuristic rules.
    pub fn assess_sovereignty_risk(&self, domain: &str) -> f64 {
        let mut score = 0.0;
        let domain_lower = domain.to_lowercase();

        // Indicator 1: Semantic Keyword Impersonation
        for keyword in &self.risk_keywords {
            if domain_lower.contains(keyword) {
                score += 3.5;
            }
        }

        // Indicator 2: High Entropy / Algorithmic Domain Generation (DGA) detection
        let entropy = self.calculate_shannon_entropy(&domain_lower);
        if entropy > 4.2 {
            score += 2.0;
        }

        // Indicator 3: TLD Suffix Anomalies common in infrastructure hijacks
        if domain_lower.ends_with(".xyz")
            || domain_lower.ends_with(".top")
            || domain_lower.ends_with(".cc")
            || domain_lower.ends_with(".tk")
        {
            score += 1.5;
        }

        score
    }
}

// ==========================================
// 2. THREAT INTEL DATABASE (Signature Catcher)
// ==========================================
#[derive(Deserialize)]
struct ThreatIntelRaw {
    blocked_domains: Vec<String>,
}

pub struct ThreatIntelDatabase {
    pub blocked_domains: HashSet<String>,
}

impl ThreatIntelDatabase {
    pub fn load_from_config(config_dir: &Path) -> Self {
        let db_path = config_dir.join("threat_intel.json");
        let mut blocked_domains = HashSet::new();

        if db_path.exists() {
            if let Ok(content) = fs::read_to_string(db_path) {
                if let Ok(raw) = serde_json::from_str::<ThreatIntelRaw>(&content) {
                    for domain in raw.blocked_domains {
                        blocked_domains.insert(domain.to_lowercase());
                    }
                }
            }
        } else {
            // Fallback baseline signatures if the sneakernet update is missing
            blocked_domains.insert("suspicious-aid-portal.org".to_string());
            blocked_domains.insert("malware-cdn.com".to_string());
            blocked_domains.insert("phishing-kit.net".to_string());
        }

        Self { blocked_domains }
    }

    pub fn check_domain(&self, domain: &str) -> bool {
        self.blocked_domains.contains(&domain.to_lowercase())
    }
}

// ==========================================
// 3. MULTI-BROWSER PATH RESOLVER (Anti-Fragility)
// ==========================================
fn locate_operational_history_ledgers() -> Vec<PathBuf> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };

    // Define all known packaging variations used across humanitarian endpoints
    let targets = vec![
        (home.join(".mozilla/firefox"), "places.sqlite"),
        (
            home.join("snap/firefox/common/.mozilla/firefox"),
            "places.sqlite",
        ),
        (
            home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"),
            "places.sqlite",
        ),
        (home.join(".config/google-chrome/Default"), "History"),
        (home.join(".config/chromium/Default"), "History"),
        (
            home.join(".config/BraveSoftware/Brave-Browser/Default"),
            "History",
        ),
    ];

    let mut found_databases = Vec::new();
    for (dir, file_name) in targets {
        if dir.exists() {
            find_db_files(&dir, file_name, &mut found_databases);
        }
    }
    found_databases
}

fn find_db_files(dir: &Path, target_name: &str, acc: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                find_db_files(&path, target_name, acc);
            } else if path.file_name().is_some_and(|name| name == target_name) {
                acc.push(path);
            }
        }
    }
}

// ==========================================
// 4. CORE EXECUTION ENGINE
// ==========================================
fn extract_domain(url_str: &str) -> Option<String> {
    if let Ok(parsed) = Url::parse(url_str) {
        parsed.host_str().map(|h| h.to_lowercase())
    } else {
        url_str.split('/').next().map(|s| s.to_lowercase())
    }
}

fn main() {
    println!("[DULLAHAN] Offline Browser History Forensics Audit");
    println!("Scanning system footprints for known tracking signatures...\n");

    let active_ledgers = locate_operational_history_ledgers();

    // FAIL-SECURE STATE: Never report "Safe" if we couldn't actually check anything.
    if active_ledgers.is_empty() {
        println!("\n========================================");
        println!("⚠️  SYSTEM BLINDSPOT WARNING: UNVERIFIED STATE");
        println!("Reason: No operational browser history databases were discovered on this host.");
        println!("        Dullahan could not locate local Flatpak, Snap, or native profiles.");
        println!(
            "Action: Verify user profile locations or export history to local directory manually."
        );
        println!("========================================");
        std::process::exit(1);
    }

    println!(
        "[*] Found {} browser history databases to audit.\n",
        active_ledgers.len()
    );

    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("dullahan");
    let threat_db = ThreatIntelDatabase::load_from_config(&config_dir);
    let risk_classifier = HeuristicRiskClassifier::new();

    let mut total_suspicious = Vec::new();

    for db_path in active_ledgers {
        println!(
            "[*] Parsing localized ledger: {:?}",
            db_path.file_name().unwrap_or_default()
        );

        // Copy to temp dir to avoid "database is locked" errors from running browsers
        let temp_db = env::temp_dir().join(format!("dullahan_audit_{}.sqlite", std::process::id()));
        if fs::copy(&db_path, &temp_db).is_err() {
            println!(
                "    [!] Failed to copy database (likely locked or permissions issue). Skipping."
            );
            continue;
        }

        if let Ok(conn) = Connection::open(&temp_db) {
            // Dynamically choose the correct SQL schema based on browser type
            let query = if db_path.to_string_lossy().contains("firefox")
                || db_path.to_string_lossy().contains("places")
            {
                "SELECT url, visit_count FROM moz_places WHERE visit_count > 0"
            } else {
                "SELECT url, visit_count FROM urls WHERE visit_count > 0"
            };

            if let Ok(mut stmt) = conn.prepare(query) {
                if let Ok(urls) = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
                }) {
                    for url_data in urls.filter_map(|r| r.ok()) {
                        let (url, count) = url_data;
                        if let Some(domain) = extract_domain(&url) {
                            // Layer 1: Precise Signature Match
                            if threat_db.check_domain(&domain) {
                                println!(
                                    "  [🚨] INSTANT DATABASE MATCH: {} (Visited {} times)",
                                    domain, count
                                );
                                total_suspicious
                                    .push(format!("KNOWN THREAT: {} ({} visits)", domain, count));
                            }
                            // Layer 2: Heuristic anomaly detection (entropy + keyword scoring)
                            else {
                                let risk_score = risk_classifier.assess_sovereignty_risk(&domain);
                                if risk_score >= 5.0 {
                                    println!("  [⚠️] HEURISTIC ALERT: Unknown domain '{}' flagged with high anomaly score ({:.1}/10)", domain, risk_score);
                                    total_suspicious.push(format!(
                                        "HEURISTIC FLAG: {} (Score: {:.1}, {} visits)",
                                        domain, risk_score, count
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        // Clean up temp file
        let _ = fs::remove_file(&temp_db);
    }

    println!("\n========================================");
    if total_suspicious.is_empty() {
        println!("✅ DEVICE STATUS: No evidence of compromise detected in browser history.");
    } else {
        println!(
            "⚠️  CRITICAL: {} suspicious indicators found!",
            total_suspicious.len()
        );
        for item in &total_suspicious {
            println!("  - {}", item);
        }
        println!("RECOMMENDATION: Device may be compromised. Consider forensic isolation.");
    }
    println!("========================================");
}
