use exif::{Reader, Tag};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct CoreAuditReport {
    pub file_path: String,
    pub has_gps: bool,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub camera_model: Option<String>,
    pub software: Option<String>,
    pub warnings: Vec<String>,
}

pub fn audit_file_metadata(
    file_path: &Path,
) -> Result<CoreAuditReport, Box<dyn std::error::Error>> {
    let mut report = CoreAuditReport {
        file_path: file_path.to_string_lossy().to_string(),
        has_gps: false,
        latitude: None,
        longitude: None,
        camera_model: None,
        software: None,
        warnings: Vec::new(),
    };

    let file = match std::fs::File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            report.warnings.push(format!("Could not open file: {}", e));
            return Ok(report);
        }
    };

    let reader = Reader::new();
    let mut buf_reader = std::io::BufReader::new(&file);

    if let Ok(exif) = reader.read_from_container(&mut buf_reader) {
        if let Some(_field) = exif.get_field(Tag::GPSLatitude, exif::In::PRIMARY) {
            report.has_gps = true;
            report
                .warnings
                .push("⚠️ WARNING: GPS coordinates found in image metadata!".to_string());
        }

        if let Some(field) = exif.get_field(Tag::Model, exif::In::PRIMARY) {
            report.camera_model = Some(field.display_value().to_string());
        }

        if let Some(field) = exif.get_field(Tag::Software, exif::In::PRIMARY) {
            report.software = Some(field.display_value().to_string());
        }
    } else {
        report
            .warnings
            .push("No EXIF data found or file is not a supported image format.".to_string());
    }

    Ok(report)
}
