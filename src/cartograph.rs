use maxminddb::Reader;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[path = "geo.rs"]
mod geo;

const LEAFLET_JS: &str = include_str!("../assets/leaflet.js");
const LEAFLET_CSS: &str = include_str!("../assets/leaflet.css");

#[derive(Serialize, Clone)]
pub struct DomainIntel {
    pub domain: String,
    pub ip: String,
    pub lat: f64,
    pub lon: f64,
    pub country: String,
    pub city: String,
    pub isp: String,
    pub risk_level: String,
    pub color: String,
    pub missing_headers: Vec<String>,
    pub tracker_count: usize,
}

pub fn generate_offline_threat_map(
    intel_data: Vec<DomainIntel>,
    output_path: &str,
    geo_db_path: &str,
) {
    println!("\n[DULLAHAN] Initiating offline threat landscape mapping...");

    if !Path::new(geo_db_path).exists() {
        eprintln!("Error: GeoLite2 database not found at: {}", geo_db_path);
        eprintln!("Action Required:");
        eprintln!("  1. Create a free account at maxmind.com");
        eprintln!("  2. Download GeoLite2-City.mmdb");
        eprintln!("  3. Place it in: ~/.local/share/dullahan/geo/");
        std::process::exit(1);
    }

    let reader = match Reader::open_readfile(geo_db_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Failed to load GeoLite database. It may be corrupted.");
            eprintln!("Reason: {}", e);
            std::process::exit(1);
        }
    };

    let mut markers: Vec<DomainIntel> = Vec::new();
    let hostile_countries = ["russia", "belarus", "iran", "north korea", "china"];
    let cdn_cities = ["ashburn", "frankfurt", "singapore", "dublin"];

    for mut intel in intel_data {
        let Some(info) = geo::lookup(&reader, &intel.ip) else {
            continue;
        };
        let (Some(lat), Some(lon)) = (info.lat, info.lon) else {
            continue;
        };
        intel.lat = lat;
        intel.lon = lon;

        let country_lower = info.country.to_lowercase();
        let city_lower = info.city.to_lowercase();

        // Hostile jurisdiction outranks the caller's assessment; a CDN hub only
        // upgrades an otherwise neutral rating. Anything else keeps the caller's rating.
        if hostile_countries.iter().any(|&c| country_lower.contains(c)) {
            intel.risk_level = "HIGH RISK: Hostile Jurisdiction".to_string();
            intel.color = "#ff0033".to_string();
        } else if intel.risk_level == "NEUTRAL"
            && cdn_cities.iter().any(|&c| city_lower.contains(c))
        {
            intel.risk_level = "OBFUSCATED (CDN/Cloud)".to_string();
            intel.color = "#ffaa00".to_string();
        }

        intel.country = info.country;
        intel.city = info.city;
        markers.push(intel);
    }

    println!("[INFO] Mapped {} coordinates.", markers.len());

    // The dashboard template loads leaflet from the same directory
    let out_dir = Path::new(output_path).parent().unwrap_or(Path::new("."));
    let _ = fs::write(out_dir.join("leaflet.js"), LEAFLET_JS);
    let _ = fs::write(out_dir.join("leaflet.css"), LEAFLET_CSS);

    let html = generate_dashboard_html(&markers);
    match fs::write(output_path, html) {
        Ok(_) => println!("[SUCCESS] Tactical dashboard rendered to: {}", output_path),
        Err(e) => eprintln!("Error: Could not write dashboard file. ({})", e),
    }
}

fn generate_dashboard_html(markers: &[DomainIntel]) -> String {
    // Load the HTML template (embedded at compile time)
    let template = include_str!("../templates/dashboard.html");

    // Build the sidebar HTML
    let mut sidebar_html = String::new();
    for (idx, m) in markers.iter().enumerate() {
        let header_status = if m.missing_headers.is_empty() {
            "<span style=\"color: #00ff41;\">[SECURE]</span>".to_string()
        } else {
            format!(
                "<span style=\"color: #ff0033;\">[MISSING: {}]</span>",
                m.missing_headers.join(", ")
            )
        };

        let tracker_status = if m.tracker_count > 0 {
            format!(
                "<span style=\"color: #ffaa00;\">[{} DETECTED]</span>",
                m.tracker_count
            )
        } else {
            "<span style=\"color: #00ff41;\">[NONE]</span>".to_string()
        };

        sidebar_html.push_str(&format!(
            "<div class=\"dossier-card\" id=\"dossier-{}\" onclick=\"focusMap({}, {})\" style=\"border-left: 3px solid {};\">\
            <div class=\"dossier-header\" style=\"color: {};\">> {}</div>\
            <div class=\"dossier-row\"><span class=\"label\">IP:</span> {}</div>\
            <div class=\"dossier-row\"><span class=\"label\">LOC:</span> {}, {}</div>\
            <div class=\"dossier-row\"><span class=\"label\">RISK:</span> {}</div>\
            <div class=\"dossier-row\"><span class=\"label\">ISP:</span> {}</div>\
            <div class=\"dossier-row\"><span class=\"label\">HDRS:</span> {}</div>\
            <div class=\"dossier-row\"><span class=\"label\">TRK:</span> {}</div>\
            </div>",
            idx, m.lat, m.lon, m.color, m.color, m.domain, m.ip, m.city, m.country,
            m.risk_level, m.isp, header_status, tracker_status
        ));
    }

    // Convert markers to JSON
    let markers_json = serde_json::to_string(markers).unwrap_or_else(|_| "[]".to_string());

    // Simple string replacement - no format! escaping needed
    template
        .replace("SIDEBAR_PLACEHOLDER", &sidebar_html)
        .replace("MARKERS_PLACEHOLDER", &markers_json)
}
