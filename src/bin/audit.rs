use exif::{Reader, Tag};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[path = "../strip.rs"]
mod strip;

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
                    current_coords.push_str(&format!(
                        "{}: {}",
                        field.tag,
                        field.display_value().with_unit(&exif)
                    ));
                }
                Tag::Model | Tag::Make | Tag::Software => {
                    let info = report.device_info.get_or_insert_with(String::new);
                    if !info.is_empty() {
                        info.push_str(", ");
                    }
                    info.push_str(&format!(
                        "{}: {}",
                        field.tag,
                        field.display_value().with_unit(&exif)
                    ));
                }
                _ => {}
            }
        }
    }

    Ok(report)
}

/// Writes a metadata-free copy of `input` and verifies it. The original is never modified.
fn strip_file(input: &str, output: Option<&str>) {
    let in_path = Path::new(input);
    let ext = in_path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let out_path = match output {
        Some(o) => PathBuf::from(o),
        None => {
            let stem = in_path.file_stem().unwrap_or_default().to_string_lossy();
            in_path.with_file_name(format!("{}.clean.{}", stem, ext))
        }
    };
    if out_path.exists() {
        eprintln!(
            "[ERROR] Output file already exists, refusing to overwrite: {}",
            out_path.display()
        );
        std::process::exit(1);
    }

    let data = match fs::read(in_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[ERROR] Could not read {}: {}", input, e);
            std::process::exit(1);
        }
    };

    let cleaned = match ext.as_str() {
        "jpg" | "jpeg" => strip::strip_jpeg(&data),
        "png" => strip::strip_png(&data),
        _ => Err(format!(
            "'.{}' files are not supported yet (JPEG and PNG only). Use: exiftool -all= <file>",
            ext
        )),
    };
    let cleaned = match cleaned {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] Could not clean file: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = fs::write(&out_path, &cleaned) {
        eprintln!("[ERROR] Could not write {}: {}", out_path.display(), e);
        std::process::exit(1);
    }

    // Verify rather than assume: re-audit the cleaned copy
    let out_str = out_path.to_string_lossy();
    match audit_file_metadata(&out_str) {
        Ok(r) if r.gps_found || r.device_info.is_some() => {
            let _ = fs::remove_file(&out_path);
            eprintln!("[ERROR] Metadata still present after cleaning. Cleaned copy deleted; do NOT share this file.");
            std::process::exit(1);
        }
        Ok(_) => {
            println!("✅ Cleaned copy written: {}", out_path.display());
            println!(
                "   Removed {} bytes of metadata. Location and device info: none found.",
                data.len() - cleaned.len()
            );
            println!("   The original file was not changed. Share the cleaned copy, then delete the original if it is no longer needed.");
            println!("   Note: photos may display rotated, because the orientation tag is part of the removed metadata.");
        }
        Err(e) => {
            let _ = fs::remove_file(&out_path);
            eprintln!(
                "[ERROR] Could not verify the cleaned copy ({}). Cleaned copy deleted.",
                e
            );
            std::process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 3 && args[1] == "--strip" {
        strip_file(&args[2], args.get(3).map(String::as_str));
        return;
    }
    if args.len() < 2 {
        eprintln!("Dullahan Metadata & EXIF Auditor (100% Offline)");
        eprintln!(
            "Usage: audit <path_to_image>                 Check a file for location/device data"
        );
        eprintln!("       audit --strip <image> [output_file]   Write a copy with metadata removed (JPEG/PNG)");
        eprintln!("\nThis tool operates entirely offline. No network requests are made.");
        std::process::exit(1);
    }

    let target_file = &args[1];
    println!(
        "[DULLAHAN] Commencing pure offline metadata audit of: {}",
        target_file
    );

    match audit_file_metadata(target_file) {
        Ok(report) => {
            println!("\n========================================");
            println!("         METADATA AUDIT REPORT          ");
            println!("========================================");
            println!("File: {}", report.file);

            if !report.safe_to_transmit {
                println!("\n⚠️  CRITICAL WARNING: UNSAFE TO TRANSMIT  ⚠️");
                if report.gps_found {
                    println!(
                        "  [!] GPS Coordinates Detected: {}",
                        report.coordinates.unwrap_or_default()
                    );
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
                println!("Command: audit --strip {}", report.file);
            }
        }
        Err(e) => {
            eprintln!("\n[ERROR] Failed to audit file: {}", e);
            eprintln!("Note: This tool currently supports JPEG, TIFF, HEIC, and other EXIF-containing formats.");
        }
    }
}
