use rusqlite::Connection;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use url::Url;

#[allow(dead_code)]
#[path = "../forensics.rs"]
mod forensics;
#[path = "../threat_intel.rs"]
mod threat_intel;

use threat_intel::ThreatIntelDatabase;

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
// 2. CORE EXECUTION ENGINE
// ==========================================
fn extract_domain(url_str: &str) -> Option<String> {
    if let Ok(parsed) = Url::parse(url_str) {
        parsed.host_str().map(|h| h.to_lowercase())
    } else {
        url_str.split('/').next().map(|s| s.to_lowercase())
    }
}

fn wal_path(db: &std::path::Path) -> PathBuf {
    let mut p = db.as_os_str().to_owned();
    p.push("-wal");
    PathBuf::from(p)
}

fn main() {
    println!("[DULLAHAN] Offline Browser History Forensics Audit");
    println!("Scanning system footprints for known tracking signatures...\n");

    let active_ledgers = forensics::locate_history_databases();

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
    if threat_db.sources.is_empty() {
        println!(
            "[!] No threat-intelligence feed installed in {}.",
            config_dir.display()
        );
        println!("    Only heuristic checks will run; known-bad domains will NOT be recognised.");
        println!("    Add threat_intel.json (generate_threat_intel.py) or threat_intel.txt (hosts/plain list).\n");
    } else {
        println!(
            "[*] Loaded {} threat signatures from {} feed file(s).\n",
            threat_db.blocked_domains.len(),
            threat_db.sources.len()
        );
    }
    let risk_classifier = HeuristicRiskClassifier::new();

    let mut total_suspicious = Vec::new();
    let mut audited = 0;

    for db in active_ledgers {
        let db_path = db.path;
        let audited_before = audited;
        println!("[*] Parsing {} ledger: {}", db.browser, db_path.display());

        // Copy to temp dir to avoid "database is locked" errors from running browsers
        let temp_db = env::temp_dir().join(format!("dullahan_audit_{}.sqlite", std::process::id()));
        let temp_wal = wal_path(&temp_db);
        if fs::copy(&db_path, &temp_db).is_err() {
            println!(
                "    [!] Failed to copy database (likely locked or permissions issue). Skipping."
            );
            continue;
        }
        // Browsers keep history in WAL mode; recent visits live in the -wal file until
        // checkpointed, so copy it alongside or they'd be silently missed.
        let _ = fs::remove_file(&temp_wal);
        let _ = fs::copy(wal_path(&db_path), &temp_wal);

        if let Ok(conn) = Connection::open(&temp_db) {
            // Dynamically choose the correct SQL schema based on browser type
            let query = if db.is_firefox {
                "SELECT url, visit_count FROM moz_places WHERE visit_count > 0"
            } else {
                "SELECT url, visit_count FROM urls WHERE visit_count > 0"
            };

            if let Ok(mut stmt) = conn.prepare(query) {
                if let Ok(urls) = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
                }) {
                    audited += 1;
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
        if audited_before == audited {
            println!("    [!] Could not read history from this database. It was NOT audited.");
        }
        // Clean up temp files
        let _ = fs::remove_file(&temp_db);
        let _ = fs::remove_file(&temp_wal);
    }

    println!("\n========================================");
    if audited == 0 {
        println!("⚠️  SYSTEM BLINDSPOT WARNING: UNVERIFIED STATE");
        println!("Reason: History databases were found but none could be read.");
        println!("========================================");
        std::process::exit(1);
    }
    if total_suspicious.is_empty() {
        println!("✅ DEVICE STATUS: No evidence of compromise detected in browser history.");
        if threat_db.sources.is_empty() {
            println!("   (Heuristic checks only: no threat feed was installed.)");
        }
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
