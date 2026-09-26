// src/scanner.rs
use serde::Serialize;
use std::fs;
use std::path::Path;
use yara_x::Compiler;

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub file: String,
    pub matched_rules: Vec<String>,
    pub is_suspicious: bool,
}

/// Built-in YARA rules for common humanitarian threat scenarios
const DEFAULT_RULES: &str = r#"
rule Suspicious_EXIF_GPS {
    meta:
        description = "Detects images with embedded GPS coordinates"
        severity = "high"
    strings:
        $gps_lat = "GPSLatitude" ascii
        $gps_lon = "GPSLongitude" ascii
        $gps_ref = "GPSLatitudeRef" ascii
    condition:
        any of them
}

rule Embedded_Script_In_Image {
    meta:
        description = "Detects script code hidden in image metadata"
        severity = "critical"
    strings:
        $eval = "eval(" ascii
        $base64 = "base64_decode" ascii
        $script = "<script" ascii nocase
        $exec = "exec(" ascii
    condition:
        any of them
}

rule Known_Tracking_Pixel {
    meta:
        description = "Detects known tracking pixel patterns"
        severity = "medium"
    strings:
        $fb_pixel = "facebook.com/tr" ascii
        $ga_pixel = "google-analytics.com/collect" ascii
        $doubleclick = "doubleclick.net" ascii
    condition:
        any of them
}

rule Suspicious_URL_In_Metadata {
    meta:
        description = "Detects URLs embedded in file metadata"
        severity = "medium"
    strings:
        $http = "http://" ascii
        $https = "https://" ascii
        $ip_url = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
    condition:
        2 of them
}

rule Phishing_Kit_Indicator {
    meta:
        description = "Detects common phishing kit patterns"
        severity = "critical"
    strings:
        $login = "login.php" ascii nocase
        $credential = "password" ascii nocase
        $post_data = "$_POST" ascii
        $mail_send = "mail(" ascii
    condition:
        3 of them
}
"#;

pub fn scan_file(file_path: &Path) -> Result<ScanResult, String> {
    let mut compiler = Compiler::new();
    compiler
        .add_source(DEFAULT_RULES)
        .map_err(|e| format!("Failed to compile YARA rules: {}", e))?;

    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);

    let file_data = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let scan_results = scanner
        .scan(&file_data)
        .map_err(|e| format!("Scan failed: {}", e))?;

    let matched_rules: Vec<String> = scan_results
        .matching_rules()
        .map(|rule| rule.identifier().to_string())
        .collect();

    Ok(ScanResult {
        file: file_path.to_string_lossy().to_string(),
        is_suspicious: !matched_rules.is_empty(),
        matched_rules,
    })
}

pub fn scan_directory(dir_path: &Path) -> Vec<ScanResult> {
    let mut results = Vec::new();

    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    let ext = ext.to_string_lossy().to_lowercase();
                    // Only scan relevant file types
                    if [
                        "jpg", "jpeg", "png", "gif", "bmp", "tiff", "pdf", "html", "htm", "php",
                        "js",
                    ]
                    .contains(&ext.as_str())
                    {
                        if let Ok(result) = scan_file(&path) {
                            if result.is_suspicious {
                                results.push(result);
                            }
                        }
                    }
                }
            }
        }
    }

    results
}
