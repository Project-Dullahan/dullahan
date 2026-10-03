use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Response, Server};

const WEB_MAP_HTML: &str = include_str!("../assets/web_map.html");
const LEAFLET_JS: &[u8] = include_bytes!("../assets/leaflet.js");
const LEAFLET_CSS: &[u8] = include_bytes!("../assets/leaflet.css");
const WORLD_MAP_JPG: &[u8] = include_bytes!("../assets/world_map.jpg");

#[derive(Clone, Serialize)]
pub struct WebDomain {
    pub name: String,
    pub risk: String,
    pub lat: f64,
    pub lon: f64,
    pub ips: Vec<String>,
    pub city: String,
    pub country: String,
    pub cert: String,
    pub market_type: String,
    pub details: String,
    /// Feed that supplied an imported threat indicator; None for analyzed domains
    pub source: Option<String>,
    /// False when no IP could be geolocated; the UI then lists it without a map pin
    pub located: bool,
    pub safemode_alerts: Vec<String>,
    pub tag: String,
}

#[derive(Clone)]
pub struct AppState {
    pub domains: Vec<WebDomain>,
    pub safemode_active: bool,
    pub verification_status: String,
    pub dns_tampered: bool,
    /// Number of flagged files from the last file scan; None until a scan has run
    pub last_file_scan_flags: Option<usize>,
    /// Number of browser history databases found by the last forensics scan
    pub last_history_dbs: Option<usize>,
}

/// Plain-language overall status. Never reports green until the checks have actually run.
fn device_status(state: &AppState) -> serde_json::Value {
    let mut problems = Vec::new();
    let mut unchecked = Vec::new();

    if state.dns_tampered {
        problems.push("Your network settings (DNS) changed while Dullahan was running. Someone may be redirecting your internet traffic. Stop using this network for sensitive work.");
    }
    match state.last_file_scan_flags {
        Some(0) => {}
        Some(_) => problems.push("Some files contain location data or hidden content. Do not share them until they are cleaned (see the flagged list)."),
        None => unchecked.push("Files have not been scanned yet. Press \"Scan EXIF Metadata\"."),
    }
    match state.last_history_dbs {
        Some(0) => {}
        Some(_) => problems.push("Browser history is stored on this device. If the device is inspected, it may reveal where you have been online."),
        None => unchecked.push("Browser history has not been checked yet. Press \"Run Browser Forensics\"."),
    }

    let (level, headline) = if state.dns_tampered {
        ("red", "DANGER: your connection may be tampered with")
    } else if !problems.is_empty() {
        ("yellow", "CAUTION: some risks found on this device")
    } else if !unchecked.is_empty() {
        ("grey", "NOT CHECKED YET: run the scans to see your status")
    } else {
        ("green", "SAFE: no problems found by the checks that ran")
    };

    let advice: Vec<&str> = problems.into_iter().chain(unchecked).collect();
    serde_json::json!({ "level": level, "headline": headline, "advice": advice })
}

#[derive(Deserialize)]
struct ScanRequest {
    path: Option<String>,
}

type HttpResponse = Response<Cursor<Vec<u8>>>;

pub fn start_web_server(
    state: Arc<Mutex<AppState>>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = Server::http(format!("127.0.0.1:{}", port))?;

    println!("[+] Daemon running at http://127.0.0.1:{}", port);
    println!("[*] Open your browser to view the tactical map interface.");
    println!("[*] Press Ctrl+C to stop the daemon.");

    for mut request in server.incoming_requests() {
        let method = request.method().clone();
        // Route on the path only, ignoring any query string
        let path = request.url().split('?').next().unwrap_or("").to_string();

        let response = match (method, path.as_str()) {
            (Method::Get, "/") | (Method::Get, "/index.html") => {
                with_content_type(Response::from_string(WEB_MAP_HTML), "text/html")
            }
            (Method::Get, "/api/domains") => {
                let state = state.lock().unwrap();
                json_response(&serde_json::to_value(&state.domains).unwrap())
            }
            (Method::Get, "/api/status") => {
                let state = state.lock().unwrap();
                json_response(&serde_json::json!({
                    "safemode_active": state.safemode_active,
                    "verification_status": state.verification_status,
                    "domain_count": state.domains.len(),
                    "device_status": device_status(&state)
                }))
            }
            (Method::Post, "/api/safemode/toggle") => {
                let mut state = state.lock().unwrap();
                state.safemode_active = !state.safemode_active;
                json_response(&serde_json::json!({ "safemode_active": state.safemode_active }))
            }
            (Method::Post, "/api/scan/exif") => {
                let scan_req: Result<ScanRequest, _> = serde_json::from_reader(request.as_reader());
                let target_path = scan_req
                    .ok()
                    .and_then(|r| r.path)
                    .unwrap_or_else(|| ".".to_string());

                let path = std::path::Path::new(&target_path);
                let scan_result = if path.is_dir() {
                    crate::scanner::scan_directory(path)
                } else {
                    crate::scanner::scan_file(path).map(|r| vec![r])
                };

                match scan_result {
                    Ok(results) => {
                        let files_scanned = results.len();
                        let findings: Vec<_> =
                            results.into_iter().filter(|r| r.is_suspicious).collect();
                        state.lock().unwrap().last_file_scan_flags = Some(findings.len());
                        json_response(&serde_json::json!({
                            "success": true,
                            "files_scanned": files_scanned,
                            "findings": findings
                        }))
                    }
                    Err(e) => json_response(&serde_json::json!({ "success": false, "error": e })),
                }
            }
            (Method::Post, "/api/scan/forensics") => {
                let matches = crate::forensics::execute_system_history_scan();
                state.lock().unwrap().last_history_dbs = Some(matches.len());
                json_response(&serde_json::json!({
                    "success": true,
                    "findings_count": matches.len(),
                    "details": serde_json::to_string_pretty(&matches).unwrap_or_else(|_| format!("{} matches found", matches.len()))
                }))
            }
            (Method::Post, "/api/blocklist/export") => {
                let state = state.lock().unwrap();
                match export_blocklist(&state.domains) {
                    Ok((path, count)) => json_response(&serde_json::json!({
                        "success": true,
                        "message": format!("Exported {} high-risk domains to {}", count, path.display())
                    })),
                    Err(e) => json_response(&serde_json::json!({
                        "success": false,
                        "message": format!("Blocklist export failed: {}", e)
                    })),
                }
            }
            (Method::Get, "/leaflet.js") => {
                with_content_type(Response::from_data(LEAFLET_JS), "application/javascript")
            }
            (Method::Get, "/leaflet.css") => {
                with_content_type(Response::from_data(LEAFLET_CSS), "text/css")
            }
            (Method::Get, "/world_map.jpg") => {
                with_content_type(Response::from_data(WORLD_MAP_JPG), "image/jpeg")
            }
            _ => Response::from_string("Not Found").with_status_code(404),
        };

        let _ = request.respond(response);
    }
    Ok(())
}

/// Writes High-risk and Malicious-tagged domains to a hosts-format blocklist.
fn export_blocklist(domains: &[WebDomain]) -> std::io::Result<(std::path::PathBuf, usize)> {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("dullahan");
    fs::create_dir_all(&dir)?;
    let path = dir.join("dullahan_hosts_blocklist.txt");

    let blocked: Vec<&str> = domains
        .iter()
        .filter(|d| d.risk == "High" || d.tag == "Malicious")
        .map(|d| d.name.as_str())
        .collect();

    let mut out = format!(
        "# Dullahan Blocklist - Generated {}\n# Count: {} domains\n\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        blocked.len()
    );
    for name in &blocked {
        out.push_str(&format!("0.0.0.0 {}\n", name));
    }
    fs::write(&path, out)?;
    Ok((path, blocked.len()))
}

fn with_content_type(response: HttpResponse, content_type: &str) -> HttpResponse {
    response.with_header(Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()).unwrap())
}

fn json_response(value: &serde_json::Value) -> HttpResponse {
    with_content_type(Response::from_string(value.to_string()), "application/json")
}
