// adweight — an audit of digital illusions.
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use std::env;
use std::time::Duration;
use url::Url;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

const KNOWN_AD_TRACKER_DOMAINS: &[&str] = &[
    "doubleclick.net", "googlesyndication.com", "google-analytics.com",
    "googletagmanager.com", "googletagservices.com",
    "connect.facebook.net", "facebook.net", "adnxs.com", "taboola.com",
    "outbrain.com", "criteo.com", "criteo.net", "amazon-adsystem.com",
    "scorecardresearch.com", "adsrvr.org", "pubmatic.com", "rubiconproject.com",
    "quantserve.com", "moatads.com", "adform.net", "media.net",
    "casalemedia.com", "openx.net", "bidswitch.net", "contextweb.com",
    "smartadserver.com", "teads.tv", "adsymptotic.com", "bluekai.com", "demdex.net",
];

const TRACKING_PATH_KEYWORDS: &[&str] = &[
    "/telemetry", "/analytics", "/metrics", "/log?", "/logs", "/tr/",
    "/ad_status", "/ads/", "pagead", "browser_metrics", "beacon",
];

struct FallenResource {
    url: String,
    domain: String,
    bytes: u64,
    is_ad_tracker: bool,
    matched_by_path: bool,
    resolved_ip: String,
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
                || style.contains("position: fixed");
            
            if looks_full_page {
                discovered.push(IntrusiveIllusion {
                    manifestation: "obstructive-overlay",
                    shadow_detail: format!("Viewport-spanning cage identified (width={} height={})", w, h),
                });
            }
        }
    }

    if let Ok(sel) = Selector::parse("[class], [id]") {
        let suspect_terms = ["popup", "interstitial", "overlay-ad", "modal-ad", "cookie-consent", "onetrust-banner"];
        for el in document.select(&sel) {
            let class = el.value().attr("class").unwrap_or("").to_lowercase();
            let id = el.value().attr("id").unwrap_or("").to_lowercase();
            for term in suspect_terms {
                if class.contains(term) || id.contains(term) {
                    discovered.push(IntrusiveIllusion {
                        manifestation: "suspect-mask",
                        shadow_detail: format!("DOM element bearing tracking/consent wrapper class: {}", term),
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
    
    // Robust Google Analytics/Tag Manager detection
    let mut cursor = html;
    while let Some(pos) = cursor.find("G-") {
        if pos +12 <= cursor.len() {
            let potential_id = &cursor[pos..pos+12];
            if potential_id.chars().skip(2).all(|c| c.is_alphanumeric()) {
                structural_keys.push(("Google Analytics/Tag Manager".to_string(), potential_id.to_string()));
            }
        }
        cursor = &cursor[pos+2..];
    }
    
    // Robust Facebook Pixel detection (looks for fbq('init', '123456789012345')
    let mut fb_cursor = html;
    while let Some(pos) = fb_cursor.find("fbq('init', '") {
        let start = pos + 14; // Length of "fbq('init', '"
        if start + 15 <= fb_cursor.len() {
            let segment = &fb_cursor[start..start+15];
            if segment.chars().all(|c| c.is_numeric()) {
                structural_keys.push(("Meta/Facebook Pixel".to_string(), segment.to_string()));
            }
        }
        fb_cursor = &fb_cursor[start..];
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
    KNOWN_AD_TRACKER_DOMAINS.iter().any(|known| domain == *known || domain.ends_with(&format!(".{}", known)))
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

fn resolve_origin_ip(domain: &str) -> String {
    // Use trust-dns-resolver for safe, timeout-bound lookups instead of blocking std::net
    let resolver = match Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(r) => r,
        Err(_) => return "Resolution Failed".to_string(),
    };
    
    match resolver.lookup_ip(domain) {
        Ok(lookup) => lookup.iter().next().map(|ip| ip.to_string()).unwrap_or_else(|| "Unresolved".to_string()),
        Err(_) => "Unresolved".to_string(),
    }
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
            eprintln!("Error: Invalid URL provided.");
            std::process::exit(1);
        }
    };

    let client = Client::builder()
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to initialize HTTP client.");

    println!("[DULLAHAN] Initiating web resource audit...");
    println!("Target: {}\n", target);

    let html_body = match client.get(target).send().and_then(|r| r.error_for_status()) {
        Ok(resp) => match resp.text() {
            Ok(t) => t,
            Err(e) => { eprintln!("Error parsing response body: {}", e); std::process::exit(1); }
        },
        Err(e) => { 
            eprintln!("Error: Failed to connect to target. ({})", e); 
            std::process::exit(1); 
        }
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

    println!("Resources found: {} (analyzing first {})", resource_urls.len(), if truncated { ARCHIVE_LIMIT } else { resource_urls.len() });

    let mut resources: Vec<FallenResource> = Vec::new();
    for raw_url in &resource_urls {
        let Some(domain) = domain_of(raw_url, &base_url) else { continue; };
        let Ok(resolved) = base_url.join(raw_url) else { continue; };
        let bytes = measure_payload_weight(&client, resolved.as_str()).unwrap_or(0);
        let ip_origin = resolve_origin_ip(&domain);
        let is_ad_domain = is_known_tracker_domain(&domain);
        let is_ad_path = contains_tracking_path(resolved.as_str());
        let is_tracker = is_ad_domain || is_ad_path;

        resources.push(FallenResource {
            url: resolved.to_string(),
            domain,
            bytes,
            is_ad_tracker: is_tracker,
            matched_by_path: !is_ad_domain && is_ad_path,
            resolved_ip: ip_origin,
        });
    }

    let tracker_bytes: u64 = resources.iter().filter(|r| r.is_ad_tracker).map(|r| r.bytes).sum();
    let total_bytes = html_bytes + resources.iter().map(|r| r.bytes).sum::<u64>();
    let tracker_count = resources.iter().filter(|r| r.is_ad_tracker).count();
    let pct = if total_bytes > 0 { (tracker_bytes as f64 / total_bytes as f64) * 100.0 } else { 0.0 };

    println!("\n=== RESOURCE ANALYSIS REPORT ===");
    println!("Target URL:          {}", target);
    println!("Base Document Size:  {} KB", html_bytes / 1024);
    println!("Total Resources:     {} (Analyzed: {})", resource_urls.len(), resources.len());
    println!("Total Payload:       {} KB", total_bytes / 1024);
    println!("Tracking Payload:    {} KB ({:.1}% of total)", tracker_bytes / 1024, pct);
    println!("================================\n");

    if !fingerprints.is_empty() {
        println!("[WARNING] Corporate tracking identifiers detected:");
        for (provider, id) in &fingerprints {
            println!("  - {}: {}", provider, id);
        }
        println!("--------------------------------");
    }

    if tracker_count > 0 {
        println!("[INFO] Identified tracking resources:");
        for r in resources.iter().filter(|r| r.is_ad_tracker) {
            let label = if r.matched_by_path { "PATH_MATCH" } else { "DOMAIN_MATCH" };
            // Added r.url to show the exact resource path being flagged
            println!("  [{:>4} KB] [{}] {} -> {} (IP: {})", r.bytes / 1024, label, r.domain, r.url, r.resolved_ip);
        }
    } else {
        println!("[INFO] No known tracking signatures detected in this scan.");
    }

    println!("\n=== DARK PATTERN ANALYSIS ===");
    if found_illusions.is_empty() {
        println!("[PASS] No obstructive overlays or aggressive consent mechanisms detected.");
    } else {
        println!("[WARNING] {} potential dark patterns detected:", found_illusions.len());
        for pattern in &found_illusions {
            println!("  - [{}] {}", pattern.manifestation, pattern.shadow_detail);
        }
    }
    println!("================================");
}
