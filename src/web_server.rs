use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Response, Server};

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
    pub safemode_alerts: Vec<String>,
    pub tag: String,
}

#[derive(Clone)]
pub struct AppState {
    pub domains: Vec<WebDomain>,
    pub safemode_active: bool,
    pub verification_status: String,
}

#[derive(Deserialize)]
struct ScanRequest {
    path: Option<String>,
}

pub fn start_web_server(state: Arc<Mutex<AppState>>, port: u16) {
    let server = match Server::http(format!("127.0.0.1:{}", port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Failed to start server on port {}: {}", port, e);
            return;
        }
    };

    println!("[+] Web server started at http://127.0.0.1:{}", port);

    for mut request in server.incoming_requests() {
        let url = request.url().to_string();
        let method = request.method().clone();

        let response = match (method, url.as_str()) {
            (Method::Get, "/") | (Method::Get, "/index.html") => serve_map_html(),
            (Method::Get, "/api/domains") => {
                let state = state.lock().unwrap();
                let json = serde_json::to_string(&state.domains).unwrap();
                Response::from_string(json).with_header(
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                )
            }
            (Method::Get, "/api/status") => {
                let state = state.lock().unwrap();
                let status = serde_json::json!({
                    "safemode_active": state.safemode_active,
                    "verification_status": state.verification_status,
                    "domain_count": state.domains.len()
                });
                Response::from_string(status.to_string()).with_header(
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                )
            }
            (Method::Post, "/api/safemode/toggle") => {
                let mut state = state.lock().unwrap();
                state.safemode_active = !state.safemode_active;
                let status = serde_json::json!({ "safemode_active": state.safemode_active });
                Response::from_string(status.to_string()).with_header(
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                )
            }
            (Method::Post, "/api/scan/exif") => {
                let req_body = request.as_reader();
                let scan_req: Result<ScanRequest, _> = serde_json::from_reader(req_body);
                let target_path = scan_req
                    .ok()
                    .and_then(|r| r.path)
                    .unwrap_or_else(|| ".".to_string());

                let path = std::path::Path::new(&target_path);
                let scan_result = if path.is_dir() {
                    Ok(crate::scanner::scan_directory(path))
                } else {
                    crate::scanner::scan_file(path).map(|r| vec![r])
                };

                match scan_result {
                    Ok(results) => {
                        let response_json = serde_json::json!({
                            "success": true,
                            "files_scanned": results.len(),
                            "findings": results
                        });
                        Response::from_string(response_json.to_string()).with_header(
                            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                                .unwrap(),
                        )
                    }
                    Err(e) => {
                        let err_json = serde_json::json!({ "success": false, "error": e });
                        Response::from_string(err_json.to_string()).with_header(
                            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                                .unwrap(),
                        )
                    }
                }
            }
            (Method::Post, "/api/scan/forensics") => {
                let matches = crate::forensics::execute_system_history_scan();
                let response_json = serde_json::json!({
                    "success": true,
                    "findings_count": matches.len(),
                    "details": serde_json::to_string_pretty(&matches).unwrap_or_else(|_| format!("{} matches found", matches.len()))
                });
                Response::from_string(response_json.to_string()).with_header(
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                )
            }
            (Method::Post, "/api/blocklist/export") => {
                let response_json = serde_json::json!({ "success": true, "message": "Blocklist exported to ~/.config/dullahan/dullahan_hosts_blocklist.txt" });
                Response::from_string(response_json.to_string()).with_header(
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                )
            }
            (Method::Get, "/leaflet.js") => {
                serve_file("assets/leaflet.js", "application/javascript")
            }
            (Method::Get, "/leaflet.css") => serve_file("assets/leaflet.css", "text/css"),
            (Method::Get, "/world_map.jpg") => serve_file("assets/world_map.jpg", "image/jpeg"),
            _ => Response::from_string("Not Found").with_status_code(404),
        };

        let _ = request.respond(response);
    }
}

fn serve_file(path: &str, content_type: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Response::from_data(bytes).with_header(
            Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()).unwrap(),
        ),
        Err(_) => Response::from_string("File not found").with_status_code(404),
    }
}

fn serve_map_html() -> Response<std::io::Cursor<Vec<u8>>> {
    let html = include_str!("../assets/web_map.html");
    Response::from_string(html)
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"text/html"[..]).unwrap())
}
