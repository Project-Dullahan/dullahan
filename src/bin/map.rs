// src/bin/map.rs
use base64::{engine::general_purpose, Engine as _};
use dirs;
use maxminddb::geoip2::City;
use maxminddb::Reader;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

// Embed all assets directly into the binary at compile time
const MAXMIND_DB: &[u8] = include_bytes!("../../assets/GeoLite2-City.mmdb");
const BASELINE_JSON: &str = include_str!("../../assets/baseline.json");
const LEAFLET_JS: &str = include_str!("../../assets/leaflet.js");
const LEAFLET_CSS: &str = include_str!("../../assets/leaflet.css");
const WORLD_MAP_IMG: &[u8] = include_bytes!("../../assets/world_map.jpg");

#[derive(Deserialize, Debug)]
struct BaselineConfig {
    generated_at: String,
    trusted_profiles: HashMap<String, DomainProfile>,
}

#[derive(Deserialize, Debug)]
struct DomainProfile {
    expected_ips: Vec<String>,
    #[serde(default)]
    expected_cert_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct MappedNode {
    domain: String,
    ip: String,
    lat: f64,
    lon: f64,
    city: String,
    country: String,
    cert: String,
}

fn main() {
    println!("[*] Loading embedded MaxMind database...");
    let reader = Reader::from_source(MAXMIND_DB).expect("Failed to load embedded MaxMind DB");

    println!("[*] Parsing embedded baseline.json...");
    let baseline: BaselineConfig = serde_json::from_str(BASELINE_JSON).expect("Failed to parse baseline");

    // Check if the TUI passed a filter file
    let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("dullahan");
    let filter_path = config_dir.join("map_filter.txt");
    let mut target_domains: Option<HashSet<String>> = None;
    
    if filter_path.exists() {
        println!("[*] Detected TUI filter. Mapping only selected domains...");
        if let Ok(content) = fs::read_to_string(&filter_path) {
            let domains: HashSet<String> = content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.trim().to_string())
                .collect();
            target_domains = Some(domains);
        }
    } else {
        println!("[*] No TUI filter detected. Mapping all baseline domains...");
    }

    let mut nodes: Vec<MappedNode> = Vec::new();

    println!("[*] Geolocating infrastructure nodes (100% offline)...");
    for (domain, profile) in baseline.trusted_profiles {
        // If a filter exists, skip domains not in the filter
        if let Some(ref targets) = target_domains {
            if !targets.contains(&domain) {
                continue;
            }
        }

        for ip in profile.expected_ips {
            if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
                if let Ok(city) = reader.lookup::<City>(ip_addr) {
                    let loc = city.location.as_ref();
                    let lat = loc.and_then(|l| l.latitude).unwrap_or(0.0);
                    let lon = loc.and_then(|l| l.longitude).unwrap_or(0.0);
                    
                    let city_name = city.city
                        .as_ref()
                        .and_then(|c| c.names.as_ref())
                        .and_then(|n| n.get("en").map(|s| s.to_string()))
                        .unwrap_or_else(|| "Unknown".to_string());
                        
                    let country_name = city.country
                        .as_ref()
                        .and_then(|c| c.names.as_ref())
                        .and_then(|n| n.get("en").map(|s| s.to_string()))
                        .unwrap_or_else(|| "Unknown".to_string());

                    nodes.push(MappedNode {
                        domain: domain.clone(),
                        ip,
                        lat,
                        lon,
                        city: city_name,
                        country: country_name,
                        cert: profile.expected_cert_sha256
                            .as_deref()
                            .map(|s| s.chars().take(16).collect::<String>() + "...")
                            .unwrap_or_else(|| "Unknown".to_string()),
                    });
                }
            }
        }
    }

    println!("[*] Embedding world map as Base64...");
    let map_b64 = general_purpose::STANDARD.encode(WORLD_MAP_IMG);
    let map_data_uri = format!("data:image/jpeg;base64,{}", map_b64);

    let nodes_json = serde_json::to_string(&nodes).unwrap();

    println!("[*] Generating self-contained HTML...");
    let html = format!(r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Dullahan Tactical Map</title>
<style>
body {{ margin:0; padding:0; background:#0d1117; color:#c9d1d9; font-family:monospace; }}
#header {{ background:#161b22; padding:10px 20px; border-bottom:1px solid #30363d; }}
#header h1 {{ margin:0; color:#58a6ff; font-size:16px; }}
#header p {{ margin:5px 0 0 0; font-size:12px; color:#8b949e; }}
#map {{ height:calc(100vh - 60px); width:100%; background:#0d1117; }}
#sidebar {{ position:absolute; top:60px; right:10px; width:280px; background:rgba(22,27,34,0.95);
  border:1px solid #30363d; border-radius:6px; padding:10px; max-height:calc(100vh - 80px);
  overflow-y:auto; z-index:1000; font-size:12px; }}
.node {{ padding:8px; margin-bottom:6px; background:#0d1117; border:1px solid #30363d; border-radius:4px; }}
.node strong {{ color:#58a6ff; }}
.meta {{ color:#8b949e; font-size:11px; }}
.leaflet-container {{ background:#0d1117 !important; }}
</style>
<style>
{leaflet_css}
</style>
<script>
{leaflet_js}
</script>
</head>
<body>
<div id="header">
  <h1>DULLAHAN TACTICAL INFRASTRUCTURE MAP</h1>
  <p>Generated: {generated_at} | Nodes: {node_count} | 100% Offline & Self-Contained</p>
</div>
<div id="map"></div>
<div id="sidebar"><strong>Tracked Infrastructure</strong><div id="node-list"></div></div>
<script>
var nodes = {nodes_json};

var map = L.map('map', {{
    center: [20, 0],
    zoom: 2,
    minZoom: 1,
    maxZoom: 4,
    zoomControl: true
}});

L.imageOverlay('{map_data_uri}', [[-90, -180], [90, 180]], {{
    attribution: 'Public Domain Equirectangular Map',
    interactive: false
}}).addTo(map);

var list = document.getElementById('node-list');
nodes.forEach(function(n) {{
    L.circleMarker([n.lat, n.lon], {{
        radius: 8, fillColor: '#3fb950', color: '#fff', weight: 1, fillOpacity: 0.8
    }}).addTo(map).bindPopup(
        '<strong>' + n.domain + '</strong><br>' +
        'IP: ' + n.ip + '<br>' +
        'Location: ' + n.city + ', ' + n.country + '<br>' +
        'Cert: ' + n.cert
    );

    var div = document.createElement('div');
    div.className = 'node';
    div.innerHTML = '<strong>' + n.domain + '</strong>' +
        '<div class="meta">IP: ' + n.ip + '</div>' +
        '<div class="meta">' + n.city + ', ' + n.country + '</div>';
    list.appendChild(div);
}});
</script>
</body>
</html>"#,
    leaflet_css = LEAFLET_CSS,
    leaflet_js = LEAFLET_JS,
    generated_at = baseline.generated_at,
    node_count = nodes.len(),
    nodes_json = nodes_json,
    map_data_uri = map_data_uri,
);

    fs::write("dullahan_map.html", html).expect("Failed to write map file");
    println!("[+] SUCCESS: Generated fully self-contained 'dullahan_map.html'");
}
