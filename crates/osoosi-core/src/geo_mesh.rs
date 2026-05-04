use std::sync::Arc;
use tokio::sync::RwLock;
use serde::Deserialize;
use tracing::{info, warn};

/// Haversine formula to calculate distance between two coordinates in km.
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371.0; // Earth radius in km
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    r * c
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeoRelayEntry {
    pub url: String,
    pub lat: f64,
    pub lon: f64,
}

pub struct GeoRelayDirectory {
    entries: Arc<RwLock<Vec<GeoRelayEntry>>>,
}

impl GeoRelayDirectory {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Load relays from a CSV string (BitChat format: URL,Lat,Lon)
    pub async fn load_csv(&self, csv: &str) {
        let mut new_entries = Vec::new();
        for line in csv.lines() {
            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if parts.len() >= 3 {
                if let (Ok(lat), Ok(lon)) = (parts[1].parse::<f64>(), parts[2].parse::<f64>()) {
                    new_entries.push(GeoRelayEntry {
                        url: parts[0].to_string(),
                        lat,
                        lon,
                    });
                }
            }
        }
        let mut entries = self.entries.write().await;
        *entries = new_entries;
        info!("GeoRelayDirectory: Loaded {} relays", entries.len());
    }

    /// Find the closest N relays to a given coordinate.
    pub async fn closest_relays(&self, lat: f64, lon: f64, count: usize) -> Vec<String> {
        let entries = self.entries.read().await;
        let mut sorted = entries.clone();
        sorted.sort_by(|a, b| {
            let dist_a = haversine_km(lat, lon, a.lat, a.lon);
            let dist_b = haversine_km(lat, lon, b.lat, b.lon);
            dist_a.partial_cmp(&dist_b).unwrap_or(std::cmp::Ordering::Equal)
        });

        sorted.into_iter().take(count).map(|e| e.url).collect()
    }

    /// Detect local public IP and geolocate it (fallback to default relays on failure).
    pub async fn auto_bootstrap(&self) -> Vec<String> {
        // In a real implementation, we would use a service like ip-api.com or similar.
        // For Oshoosi, we will attempt to fetch local geo info if OSOOSI_GEO_BOOTSTRAP is set.
        if std::env::var("OSOOSI_GEO_BOOTSTRAP").is_err() {
            return Vec::new();
        }

        match reqwest::get("http://ip-api.com/json").await {
            Ok(resp) => {
                #[derive(Deserialize)]
                struct IpGeo {
                    lat: f64,
                    lon: f64,
                }
                if let Ok(geo) = resp.json::<IpGeo>().await {
                    info!("GeoRelayDirectory: Detected location ({}, {})", geo.lat, geo.lon);
                    return self.closest_relays(geo.lat, geo.lon, 5).await;
                }
            }
            Err(e) => warn!("GeoRelayDirectory: Failed to geolocate IP: {}", e),
        }
        Vec::new()
    }
}
