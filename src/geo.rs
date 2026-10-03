use maxminddb::geoip2::City;
use maxminddb::Reader;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub struct GeoInfo {
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub city: String,
    pub country: String,
}

fn english_name(names: Option<BTreeMap<&str, &str>>) -> String {
    names
        .and_then(|n| n.get("en").map(|s| s.to_string()))
        .unwrap_or_else(|| "Unknown".to_string())
}

/// Offline GeoLite2 lookup. Returns None if the IP is unparseable or not in the database.
pub fn lookup<S: AsRef<[u8]>>(reader: &Reader<S>, ip: &str) -> Option<GeoInfo> {
    let ip: IpAddr = ip.parse().ok()?;
    let city = reader.lookup::<City>(ip).ok()?;
    let loc = city.location.as_ref();
    Some(GeoInfo {
        lat: loc.and_then(|l| l.latitude),
        lon: loc.and_then(|l| l.longitude),
        city: english_name(city.city.and_then(|c| c.names)),
        country: english_name(city.country.and_then(|c| c.names)),
    })
}
