use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct ThreatIntelRaw {
    blocked_domains: Vec<String>,
}

pub struct ThreatIntelDatabase {
    pub blocked_domains: HashSet<String>,
    /// Feed files that were loaded; empty means no signatures are installed.
    pub sources: Vec<PathBuf>,
}

impl ThreatIntelDatabase {
    /// Loads every feed found in `config_dir`:
    /// - `threat_intel.json`: `{"blocked_domains": [...]}` (from generate_threat_intel.py)
    /// - `threat_intel.txt`: one domain per line, or hosts format (`0.0.0.0 domain`), `#` comments
    ///
    /// Feeds are carried in offline (e.g. on encrypted removable media).
    pub fn load_from_config(config_dir: &Path) -> Self {
        let mut db = Self {
            blocked_domains: HashSet::new(),
            sources: Vec::new(),
        };

        let json_path = config_dir.join("threat_intel.json");
        if let Ok(content) = fs::read_to_string(&json_path) {
            match serde_json::from_str::<ThreatIntelRaw>(&content) {
                Ok(raw) => {
                    db.add_all(raw.blocked_domains.iter().map(String::as_str));
                    db.sources.push(json_path);
                }
                Err(e) => eprintln!("[!] Ignoring malformed {}: {}", json_path.display(), e),
            }
        }

        let txt_path = config_dir.join("threat_intel.txt");
        if let Ok(content) = fs::read_to_string(&txt_path) {
            db.add_all(content.lines().filter_map(parse_feed_line));
            db.sources.push(txt_path);
        }

        db
    }

    fn add_all<'a>(&mut self, domains: impl Iterator<Item = &'a str>) {
        for d in domains {
            let d = d.trim().trim_end_matches('.').to_lowercase();
            if !d.is_empty() {
                self.blocked_domains.insert(d);
            }
        }
    }

    /// True if `domain` or any parent domain is listed (so `evil.com` also catches `www.evil.com`).
    pub fn check_domain(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_lowercase();
        let mut candidate = domain.as_str();
        loop {
            if self.blocked_domains.contains(candidate) {
                return true;
            }
            match candidate.split_once('.') {
                Some((_, parent)) if parent.contains('.') => candidate = parent,
                _ => return false,
            }
        }
    }
}

/// Accepts `domain`, `0.0.0.0 domain` or `127.0.0.1 domain`; skips comments and localhost entries.
fn parse_feed_line(line: &str) -> Option<&str> {
    let line = line.split('#').next()?.trim();
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    let domain = match parts.next() {
        Some(second) if first.parse::<std::net::IpAddr>().is_ok() => second,
        Some(_) => return None,
        None => first,
    };
    (!matches!(domain, "localhost" | "localhost.localdomain" | "0.0.0.0")).then_some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_listed_domain_and_subdomains_only() {
        let mut db = ThreatIntelDatabase {
            blocked_domains: HashSet::new(),
            sources: vec![],
        };
        db.add_all(["Evil.example."].into_iter());
        assert!(db.check_domain("evil.example"));
        assert!(db.check_domain("www.EVIL.example"));
        assert!(!db.check_domain("notevil.example"));
        assert!(!db.check_domain("example"));
    }

    #[test]
    fn parses_plain_and_hosts_formats() {
        assert_eq!(parse_feed_line("bad.example"), Some("bad.example"));
        assert_eq!(
            parse_feed_line("0.0.0.0 bad.example # c2"),
            Some("bad.example")
        );
        assert_eq!(parse_feed_line("127.0.0.1 localhost"), None);
        assert_eq!(parse_feed_line("# comment"), None);
        assert_eq!(parse_feed_line(""), None);
    }
}
