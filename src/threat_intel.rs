use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

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
