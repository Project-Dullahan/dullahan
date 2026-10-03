use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct ForensicMatch {
    pub browser: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub path: String,
    pub severity: String,
}

pub struct HistoryDb {
    pub browser: &'static str,
    pub is_firefox: bool,
    pub path: PathBuf,
}

/// Finds browser history databases across native, Snap and Flatpak installs.
pub fn locate_history_databases() -> Vec<HistoryDb> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };

    let targets = [
        ("Firefox", home.join(".mozilla/firefox")),
        (
            "Firefox (Snap)",
            home.join("snap/firefox/common/.mozilla/firefox"),
        ),
        (
            "Firefox (Flatpak)",
            home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"),
        ),
        ("Chrome", home.join(".config/google-chrome")),
        ("Chromium", home.join(".config/chromium")),
        ("Brave", home.join(".config/BraveSoftware/Brave-Browser")),
    ];

    let mut found = Vec::new();
    for (browser, dir) in targets {
        let is_firefox = browser.starts_with("Firefox");
        let file_name = if is_firefox {
            "places.sqlite"
        } else {
            "History"
        };
        let mut paths = Vec::new();
        find_db_files(&dir, file_name, &mut paths);
        found.extend(paths.into_iter().map(|path| HistoryDb {
            browser,
            is_firefox,
            path,
        }));
    }
    found
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

pub fn execute_system_history_scan() -> Vec<ForensicMatch> {
    locate_history_databases()
        .into_iter()
        .map(|db| ForensicMatch {
            browser: db.browser.to_string(),
            r#type: if db.is_firefox {
                "Places Database"
            } else {
                "History Database"
            }
            .to_string(),
            path: db.path.to_string_lossy().to_string(),
            severity: "Medium".to_string(),
        })
        .collect()
}
