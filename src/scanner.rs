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

const SCANNED_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "pdf", "html", "htm", "php", "js",
];

fn compile_rules() -> Result<yara_x::Rules, String> {
    let mut compiler = Compiler::new();
    compiler
        .add_source(DEFAULT_RULES)
        .map_err(|e| format!("Failed to compile YARA rules: {}", e))?;
    Ok(compiler.build())
}

fn scan_with_rules(rules: &yara_x::Rules, file_path: &Path) -> Result<ScanResult, String> {
    let mut scanner = yara_x::Scanner::new(rules);

    let file_data = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let scan_results = scanner
        .scan(&file_data)
        .map_err(|e| format!("Scan failed: {}", e))?;

    let mut matched_rules: Vec<String> = scan_results
        .matching_rules()
        .map(|rule| rule.identifier().to_string())
        .collect();

    // EXIF stores GPS as numeric tags, not the text "GPSLatitude", so YARA string rules
    // cannot see it in real photos. Parse the EXIF block properly instead.
    if has_gps_exif(&file_data) {
        matched_rules.push("GPS_Location_In_EXIF".to_string());
    }

    Ok(ScanResult {
        file: file_path.to_string_lossy().to_string(),
        is_suspicious: !matched_rules.is_empty(),
        matched_rules,
    })
}

fn has_gps_exif(file_data: &[u8]) -> bool {
    exif::Reader::new()
        .read_from_container(&mut std::io::Cursor::new(file_data))
        .map(|exif| {
            exif.fields()
                .any(|f| matches!(f.tag, exif::Tag::GPSLatitude | exif::Tag::GPSLongitude))
        })
        .unwrap_or(false)
}

pub fn scan_file(file_path: &Path) -> Result<ScanResult, String> {
    scan_with_rules(&compile_rules()?, file_path)
}

/// Scans every supported file in `dir_path` (non-recursive) and returns a result per file.
pub fn scan_directory(dir_path: &Path) -> Result<Vec<ScanResult>, String> {
    let rules = compile_rules()?;
    let entries = fs::read_dir(dir_path).map_err(|e| format!("Failed to read directory: {}", e))?;

    let mut results = Vec::new();
    for path in entries.flatten().map(|e| e.path()) {
        let supported = path.is_file()
            && path.extension().is_some_and(|ext| {
                SCANNED_EXTENSIONS.contains(&ext.to_string_lossy().to_lowercase().as_str())
            });
        if supported {
            if let Ok(result) = scan_with_rules(&rules, &path) {
                results.push(result);
            }
        }
    }
    Ok(results)
}
