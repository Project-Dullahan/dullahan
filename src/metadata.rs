use exif::{Reader, Tag};
use std::fs;
use std::path::Path;

pub struct CoreAuditReport {
    pub file_name: String,
    pub gps_found: bool,
    pub coordinates: Option<String>,
    pub device_info: Option<String>,
    pub safe_to_transmit: bool,
}

/// A 100% offline, deterministic metadata parser.
/// Zero network footprint. Zero guesswork.
pub fn audit_file_metadata(file_path: &Path) -> Result<CoreAuditReport, Box<dyn std::error::Error>> {
    if !file_path.exists() {
        return Err("Target asset does not exist on disk".into());
    }

    let mut report = CoreAuditReport {
        file_name: file_path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        gps_found: false,
        coordinates: None,
        device_info: None,
        safe_to_transmit: true,
    };

    let file = fs::File::open(file_path)?;
    let mut buf_reader = std::io::BufReader::new(file);
    
    if let Ok(exif) = Reader::new().read_from_container(&mut buf_reader) {
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
