use maxminddb::geoip2::City;
use maxminddb::Reader;
use serde::Serialize;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

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

pub fn generate_offline_threat_map(intel_data: Vec<DomainIntel>, output_path: &str, geo_db_path: &str) {
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

    for mut intel in intel_data {
        if let Ok(ip) = intel.ip.parse::<IpAddr>() {
            if let Ok(city_data) = reader.lookup::<City>(ip) {
                let country = city_data.country
                    .and_then(|c| c.names)
                    .and_then(|n| n.get("en").map(|s| s.to_string()))
                    .unwrap_or_else(|| "Unknown".to_string());

                let city = city_data.city
                    .and_then(|c| c.names)
                    .and_then(|n| n.get("en").map(|s| s.to_string()))
                    .unwrap_or_else(|| "Unknown".to_string());

                let isp = "Unknown (GeoLite2 Free)".to_string();

                if let Some(loc) = city_data.location {
                    if let (Some(lat), Some(lon)) = (loc.latitude, loc.longitude) {
                        intel.lat = lat;
                        intel.lon = lon;
                        intel.country = country.clone();
                        intel.city = city.clone();
                        intel.isp = isp.clone();

                        let country_lower = country.to_lowercase();
                        let city_lower = city.to_lowercase();
                        let isp_lower = isp.to_lowercase();

                        let (risk_level, color) = if hostile_countries.iter().any(|&c| country_lower.contains(c)) {
                            ("HIGH RISK: Hostile Jurisdiction".to_string(), "#ff0033".to_string())
                        } else if isp_lower.contains("military") || isp_lower.contains("gov") || isp_lower.contains("state") {
                            ("HIGH RISK: Gov/Military Infra".to_string(), "#ff0033".to_string())
                        } else if city_lower.contains("ashburn") || city_lower.contains("frankfurt") || city_lower.contains("singapore") || city_lower.contains("dublin") || isp_lower.contains("cloudflare") || isp_lower.contains("akamai") || isp_lower.contains("amazon") {
                            ("OBFUSCATED (CDN/Cloud)".to_string(), "#ffaa00".to_string())
                        } else {
                            ("NEUTRAL".to_string(), "#00ff41".to_string())
                        };

                        intel.risk_level = risk_level;
                        intel.color = color;
                        markers.push(intel);
                    }
                }
            }
        }
    }

    println!("[INFO] Mapped {} coordinates.", markers.len());

    let home_dir = match dirs::home_dir() {
        Some(h) => h,
        None => {
            eprintln!("Warning: Could not determine home directory. Leaflet assets will not be auto-copied.");
            let html = generate_dashboard_html(&markers);
            match fs::write(output_path, html) {
                Ok(_) => println!("[SUCCESS] Tactical dashboard rendered to: {}", output_path),
                Err(e) => eprintln!("Error: Could not write dashboard file. ({})", e),
            }
            return;
        }
    };

    let web_dir = home_dir.join(".local/share/dullahan/web");
    let out_dir = Path::new(output_path).parent().unwrap_or(Path::new("."));

    if web_dir.join("leaflet.js").exists() {
        let _ = fs::copy(web_dir.join("leaflet.js"), out_dir.join("leaflet.js"));
    }
    if web_dir.join("leaflet.css").exists() {
        let _ = fs::copy(web_dir.join("leaflet.css"), out_dir.join("leaflet.css"));
    }

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
            format!("<span style=\"color: #ff0033;\">[MISSING: {}]</span>", m.missing_headers.join(", "))
        };

        let tracker_status = if m.tracker_count > 0 {
            format!("<span style=\"color: #ffaa00;\">[{} DETECTED]</span>", m.tracker_count)
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
