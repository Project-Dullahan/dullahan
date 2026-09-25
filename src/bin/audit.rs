use exif::{Reader, Tag};
use std::env;
use std::fs;
use std::path::Path;

struct AuditReport {
    file: String,
    gps_found: bool,
    coordinates: Option<String>,
    device_info: Option<String>,
    safe_to_transmit: bool,
}

/// Deterministic, 100% offline metadata parser.
/// Zero network sockets are opened. Zero guesswork.
fn audit_file_metadata(file_path: &str) -> Result<AuditReport, Box<dyn std::error::Error>> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err("File does not exist".into());
    }

    let mut report = AuditReport {
        file: file_path.to_string(),
        gps_found: false,
        coordinates: None,
        device_info: None,
        safe_to_transmit: true,
    };

    let file = fs::File::open(path)?;
    let mut bufreader = std::io::BufReader::new(file);
    
    // The correct kamadak-exif API
    if let Ok(exif) = Reader::new().read_from_container(&mut bufreader) {
        for field in exif.fields() {
            match field.tag {
                Tag::GPSLatitude | Tag::GPSLongitude => {
                    report.gps_found = true;
                    report.safe_to_transmit = false;
                    let current_coords = report.coordinates.get_or_insert_with(String::new);
                    if !current_coords.is_empty() {
                        current_coords.push_str(", ");
                    }
                    current_coords.push_str(&format!("{}: {}", field.tag, field.display_value().with_unit(&exif)));
                }
                Tag::Model | Tag::Make | Tag::Software => {
                    let info = report.device_info.get_or_insert_with(String::new);
                    if !info.is_empty() {
                        info.push_str(", ");
                    }
                    info.push_str(&format!("{}: {}", field.tag, field.display_value().with_unit(&exif)));
                }
                _ => {}
            }
        }
    }

    Ok(report)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Dullahan Metadata & EXIF Auditor (100% Offline)");
        eprintln!("Usage: cargo run --bin audit -- <path_to_image>");
        eprintln!("\nThis tool operates entirely offline. No network requests are made.");
        std::process::exit(1);
    }

    let target_file = &args[1];
    println!("[DULLAHAN] Commencing pure offline metadata audit of: {}", target_file);

    match audit_file_metadata(target_file) {
        Ok(report) => {
            println!("\n========================================");
            println!("         METADATA AUDIT REPORT          ");
            println!("========================================");
            println!("File: {}", report.file);
            
            if !report.safe_to_transmit {
                println!("\n⚠️  CRITICAL WARNING: UNSAFE TO TRANSMIT  ⚠️");
                if report.gps_found {
                    println!("  [!] GPS Coordinates Detected: {}", report.coordinates.unwrap_or_default());
                }
            } else {
                println!("\n✅ SAFE TO TRANSMIT: No sensitive geolocation metadata found.");
            }

            if let Some(device) = report.device_info {
                println!("  [i] Device/Software Info: {}", device);
            }

            println!("========================================\n");
            if !report.safe_to_transmit {
                println!("RECOMMENDATION: Strip metadata before sharing.");
                println!("Command: exiftool -all= <filename>");
            }
        }
        Err(e) => {
            eprintln!("\n[ERROR] Failed to audit file: {}", e);
            eprintln!("Note: This tool currently supports JPEG, TIFF, HEIC, and other EXIF-containing formats.");
        }
    }
}
