use std::fs::File;
use std::io::Write;

fn main() {
    let code = r#"// adweight — an audit of digital illusions.
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use std::env;
use std::time::Duration;
use url::Url;

const KNOWN_AD_TRACKER_DOMAINS: &[&str] = &[
    "doubleclick.net", "googlesyndication.com", "google-analytics.com",
    "googletagmanager.com", "googletagservices.com", "://google.com",
    "connect.facebook.net", "facebook.net", "adnxs.com", "taboola.com",
    "outbrain.com", "criteo.com", "criteo.net", "amazon-adsystem.com",
    "scorecardresearch.com", "adsrvr.org", "pubmatic.com", "rubiconproject.com",
    "quantserve.com", "moatads.com", "adform.net", "media.net",
    "casalemedia.com", "openx.net", "bidswitch.net", "contextweb.com",
    "smartadserver.com", "teads.tv", "adsymptotic.com", "bluekai.com", "demdex.net",
];

const TRACKING_PATH_KEYWORDS: &[&str] = &[
    "/telemetry", "/analytics", "/metrics", "/log?", "/logs", "/tr/",
    "/ad_status", "/ads/", "pagead", "browser_metrics", "vapi/stats", "beacon",
];

struct FallenResource {
    url: String,
    domain: String,
    bytes: u64,
    is_ad_tracker: bool,
    matched_by_path: bool,
}

struct IntrusiveIllusion {
    manifestation: &'static str,
    shadow_detail: String,
}

fn track_intrusive_illusions(document: &Html) -> Vec<IntrusiveIllusion> {
    let mut discovered = Vec::new();
    if let Ok(sel) = Selector::parse("video[autoplay]") {
        for el in document.select(&sel) {
            let has_muted = el.value().attr("muted").is_some();
            discovered.push(IntrusiveIllusion {
                manifestation: "auditory-intrusion",
                shadow_detail: if has_muted {
                    "Autoplay canvas detected (silenced/muted).".to_string()
                } else {
                    "Unmuted autoplay canvas detected—high-disruption auditory breach.".to_string()
                },
            });
        }
    }
    if let Ok(sel) = Selector::parse("iframe") {
        for el in document.select(&sel) {
            let w = el.value().attr("width").unwrap_or("");
            let h = el.value().attr("height").unwrap_or("");
            let style = el.value().attr("style").unwrap_or("");
            let looks_full_page = w.contains("100%")
                || h.contains("100%")
                || style.contains("position:fixed")
                || style.contains("position: fixed")
                || style.replace(" ", "").contains("position:fixed");
            if looks_full_page {
                discovered.push(IntrusiveIllusion {
                    manifestation: "obstructive-overlay",
                    shadow_detail: format!("Viewport-spanning cage identified (width={w:?} height={h:?})"),
                });
            }
        }
    }
    if let Ok(sel) = Selector::parse("[class], [id]") {
        let suspect_terms = ["popup", "interstitial", "overlay-ad", "modal-ad"];
        for el in document.select(&sel) {
            let class = el.value().attr("class").unwrap_or("").to_lowercase();
            let id = el.value().attr("id").unwrap_or("").to_lowercase();
            for term in suspect_terms {
                if class.contains(term) || id.contains(term) {
                    discovered.push(IntrusiveIllusion {
                        manifestation: "suspect-mask",
                        shadow_detail: format!("DOM element bearing the signature class/id: {term}"),
                    });
                    break;
                }
            }
        }
    }
    discovered
}

fn scan_for_corporate_fingerprints(html: &str) -> Vec<(String, String)> {
    let mut structural_keys = Vec::new();
    let mut cursor = html;
    while let Some(pos) = cursor.find("G-") {
        if pos + 12 <= cursor.len() {
            let potential_id = &cursor[pos..pos+12];
            if potential_id.chars().skip(2).all(|c| c.is_alphanumeric()) {
                structural_keys.push(("Google Global Tracker Token".to_string(), potential_id.to_string()));
            }
        }
        cursor = &cursor[pos+2..];
    }
    let mut fb_cursor = html;
    while let Some(pos) = fb_cursor.find("id=") {
        if pos + 18 <= fb_cursor.len() {
            let segment = &fb_cursor[pos+3..pos+18];
            if segment.chars().all(|c| c.is_numeric()) {
                structural_keys.push(("Meta Core Target Vector ID".to_string(), segment.to_string()));
            }
        }
        fb_cursor = &fb_cursor[pos+3..];
    }
    structural_keys.sort();
    structural_keys.dedup();
    structural_keys
}

fn domain_of(url_str: &str, base: &Url) -> Option<String> {
    let resolved = base.join(url_str).ok()?;
    resolved.host_str().map(|h| h.to_string())
}

fn is_known_tracker_domain(domain: &str) -> bool {
    KNOWN_AD_TRACKER_DOMAINS.iter().any(|known| domain == *known || domain.ends_with(&format!(".{known}")))
}

fn contains_tracking_path(url_str: &str) -> bool {
    let lower_url = url_str.to_lowercase();
    TRACKING_PATH_KEYWORDS.iter().any(|keyword| lower_url.contains(keyword))
}

fn measure_payload_weight(client: &Client, url: &str) -> Option<u64> {
    if let Ok(resp) = client.head(url).send() {
        if let Some(len) = resp.content_length() { if len > 0 { return Some(len); } }
    }
    if let Ok(resp) = client.get(url).send() {
        if let Some(len) = resp.content_length() { return Some(len); }
        if let Ok(bytes) = resp.bytes() { return Some(bytes.len() as u64); }
    }
    None
}

fn print_unmasked_entity() {
    println!("\n          ,      ,\n         /(.-..-.)\\\n\n    |\\  /          \\  /|    [ ENTITY UNMASKED PROTOCOL ACTIVATED ]\n    | \\/ =.      .= \\/ |\n    \\( \\   o|  |o   / )/    \"The facade peels back to reveal the single\n     \\_,    /  \\    ,_/      architectural entity masquerading across \n\n       |   /\\__/   |         the coordinates of the rotting tree.\"\n       \\  /\\____/\\  /\n        \\ \\_||_// /         Corporate Monopoly Signature Detected.\n         \\_______/          Tracking infrastructure linked to core host.\n");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: adweight <target-url>");
        std::process::exit(1);
    }
    let target = &args[1];

    let base_url = match Url::parse(target) {
        Ok(u) => u,
        Err(_) => {
            eprintln!("Fatal: URL extraction failed.");
            std::process::exit(1);
        }
    };

    let client = Client::builder()
        .user_agent("adweight/0.1 (architectural-bloat-scrutiny)")
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to initialize secure transport client.");

    println!("✦ Approaching target stream: {} ...", target);
    let html_body = match client.get(target).send().and_then(|r| r.error_for_status()) {
        Ok(resp) => match resp.text() {
            Ok(t) => t,
            Err(e) => { eprintln!("Error parsing stream body: {e}"); std::process::exit(1); }
        },
        Err(e) => { eprintln!("Failure contacting target coordinate: {e}"); std::process::exit(1); }
    };

    let html_bytes = html_body.len() as u64;
    let document = Html::parse_document(&html_body);
    let found_illusions = track_intrusive_illusions(&document);
    let fingerprints = scan_for_corporate_fingerprints(&html_body);

    let tag_attrs: &[(&str, &str)] = &[
        ("script[src]", "src"), ("img[src]", "src"),
        ("iframe[src]", "src"), ("link[rel=\"stylesheet\"][href]", "href"),
    ];

    let mut resource_urls: Vec<String> = Vec::new();
    for (selector_str, attr) in tag_attrs {
        if let Ok(selector) = Selector::parse(selector_str) {
            for el in document.select(&selector) {
                if let Some(val) = el.value().attr(attr) { resource_urls.push(val.to_string()); }
            }
        }
    }
    resource_urls.sort();
    resource_urls.dedup();

    const ARCHIVE_LIMIT: usize = 60;
    let truncated = resource_urls.len() > ARCHIVE_LIMIT;
    resource_urls.truncate(ARCHIVE_LIMIT);

    println!(
        "✦ Isolated {} linked dependency streams{}. Commencing weight measurements...\n",
        resource_urls.len(),
        if truncated { format!(" (Evaluating first {ARCHIVE_LIMIT} shadows)") } else { String::new() }
    );

    let mut resources: Vec<FallenResource> = Vec::new();
    for raw_url in &resource_urls {
        let Some(domain) = domain_of(raw_url, &base_url) else { continue; };
        let Ok(resolved) = base_url.join(raw_url) else { continue; };
        let bytes = measure_payload_weight(&client, resolved.as_str()).unwrap_or(0);
        
        let is_ad_domain = is_known_tracker_domain(&domain);
        let is_ad_path = contains_tracking_path(resolved.as_str());
        let total_ad_verdict = is_ad_domain || is_ad_path;

        resources.push(FallenResource {
            url: resolved.to_string(),
            domain,
            bytes,
            is_ad_tracker: total_ad_verdict,
            matched_by_path: !is_ad_domain && is_ad_path,
        });
    }

    let ad_bytes: u64 = resources.iter().filter(|r| r.is_ad_tracker).map(|r| r.bytes).sum();
    let other_bytes: u64 = resources.iter().filter(|r| !r.is_ad_tracker).map(|r| r.bytes).sum();
    let total_resource_bytes = ad_bytes + other_bytes;
    let total_bytes = html_bytes + total_resource_bytes;
    let ad_count = resources.iter().filter(|r| r.is_ad_tracker).count();
    let pct = if total_bytes > 0 { (ad_bytes as f64 / total_bytes as f64) * 100.0 } else { 0.0 };

    println!("============= ANATOMY OF DIGITAL ILLUSION =============");
    println!("Target Coordinate:    {}", target);
    println!("Baseline Document:    {} KB", html_bytes / 1024);
    println!("Total Active Chains:  {} ({} cataloged)", resource_urls.len(), resources.len());
    println!("Total Mortal Weight:  {} KB", total_bytes / 1024);
    println!("Tracking Vector Count:{:>5}", ad_count);
