use rusqlite::Connection;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub const KNOWN_THREATS: &[&str] = &[
    "suspicious-aid-portal.org",
    "malware-cdn.com",
    "phishing-kit.net",
];

pub struct ForensicMatch {
    pub browser: String,
    pub domain: String,
    pub count: i32,
    pub full_url: String,
}

pub fn execute_system_history_scan() -> Vec<ForensicMatch> {
    let mut matches = Vec::new();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return matches,
    };

    // Matrix abstraction to cleanly identify sandboxed/native database profiles
    // Format: (Browser Name, Search Directory, Database Target File, Is_Chromium_Engine)
    let configurations = vec![
        ("Firefox (Native)", home.join(".mozilla/firefox"), "places.sqlite", false),
        ("Firefox (Snap)", home.join("snap/firefox/common/.mozilla/firefox"), "places.sqlite", false),
        ("Firefox (Flatpak)", home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"), "places.sqlite", false),
        ("Chrome/Chromium", home.join(".config/google-chrome"), "History", true),
        ("Brave Browser", home.join(".config/BraveSoftware/Brave-Browser"), "History", true),
    ];

    for (name, base_dir, db_name, is_chromium) in configurations {
        if base_dir.exists() {
            let mut detected_paths = Vec::new();
            locate_ledgers_recursively(&base_dir, db_name, &mut detected_paths);

            for db_path in detected_paths {
                if let Ok(mut engine_results) = audit_single_db(name, &db_path, is_chromium) {
                    matches.append(&mut engine_results);
                }
            }
        }
    }
    matches
}

fn locate_ledgers_recursively(dir: &Path, target: &str, acc: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                locate_ledgers_recursively(&path, target, acc);
            } else if path.file_name().map_or(false, |name| name == target) {
                acc.push(path);
            }
        }
    }
}

fn audit_single_db(browser: &str, db_path: &Path, is_chromium: bool) -> Result<Vec<ForensicMatch>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    let temp_copy = env::temp_dir().join(format!("dullahan_fsc_tmp_{}.sqlite", browser.replace(' ', "_")));
    
    // Copy to temp dir to avoid "database is locked" errors from running browsers
    fs::copy(db_path, &temp_copy)?;
    let conn = Connection::open(&temp_copy)?;
    
    // Dynamically pivot SQL parsing logic based on underlying browser database schemas
    let query = if is_chromium {
        "SELECT url, visit_count FROM urls WHERE visit_count > 0"
    } else {
        "SELECT url, visit_count FROM moz_places WHERE visit_count > 0"
    };

    let mut stmt = conn.prepare(query)?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
    })?;

    for row in rows.flatten() {
        let url_lower = row.0.to_lowercase();
        for threat in KNOWN_THREATS {
            if url_lower.contains(threat) {
                results.push(ForensicMatch {
                    browser: browser.to_string(),
                    domain: threat.to_string(),
                    count: row.1,
                    full_url: row.0.clone(),
                });
            }
        }
    }

    // Clean up temp file
    let _ = fs::remove_file(&temp_copy);
    Ok(results)
}
