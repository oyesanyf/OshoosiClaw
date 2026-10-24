use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    middleware::Next,
    Json,
};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Token bucket configuration for a specific route category.
#[derive(Debug, Clone, Copy)]
pub struct BucketPolicy {
    /// Maximum burst capacity (number of tokens).
    pub capacity: f64,
    /// Refill rate (tokens added per second).
    pub refill_rate_per_sec: f64,
}

impl BucketPolicy {
    pub const fn new(capacity: f64, refill_rate_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_rate_per_sec,
        }
    }
}

/// State of an individual client's token bucket.
#[derive(Debug, Clone)]
pub struct ClientBucket {
    pub tokens: f64,
    pub last_update: Instant,
}

impl ClientBucket {
    pub fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
        }
    }

    /// Attempt to consume `tokens_to_consume` tokens under `policy`.
    /// Returns `Ok(())` if allowed, or `Err(wait_secs)` if throttled.
    pub fn try_consume(
        &mut self,
        policy: &BucketPolicy,
        tokens_to_consume: f64,
    ) -> Result<(), f64> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        // Refill tokens proportionally based on elapsed time up to capacity
        self.tokens = (self.tokens + elapsed * policy.refill_rate_per_sec).min(policy.capacity);

        if self.tokens >= tokens_to_consume {
            self.tokens -= tokens_to_consume;
            Ok(())
        } else {
            let deficit = tokens_to_consume - self.tokens;
            let wait_secs = (deficit / policy.refill_rate_per_sec).ceil().max(1.0);
            Err(wait_secs)
        }
    }
}

/// Thread-safe multi-tier token bucket rate limiter for Port 3030.
pub struct Port3030RateLimiter {
    auth_buckets: DashMap<String, ClientBucket>,
    heavy_buckets: DashMap<String, ClientBucket>,
    general_buckets: DashMap<String, ClientBucket>,
    auth_policy: BucketPolicy,
    heavy_policy: BucketPolicy,
    general_policy: BucketPolicy,
    total_throttled_requests: AtomicU64,
}

impl Port3030RateLimiter {
    pub fn new() -> Self {
        Self {
            auth_buckets: DashMap::new(),
            heavy_buckets: DashMap::new(),
            general_buckets: DashMap::new(),
            // Strict anti-brute-force for auth endpoints: burst 10, refill 0.33/sec (max 20 attempts/min)
            auth_policy: BucketPolicy::new(10.0, 0.333),
            // Heavy computational endpoints (REA disassembly, siquery, SkyRL retraining): burst 20, refill 1.0/sec
            heavy_policy: BucketPolicy::new(20.0, 1.0),
            // General API endpoints: burst 120, refill 20.0/sec
            general_policy: BucketPolicy::new(120.0, 20.0),
            total_throttled_requests: AtomicU64::new(0),
        }
    }

    /// Check if the request from `client_key` accessing `path` is within rate limits.
    /// Returns `Ok(())` if permitted, or `Err(retry_after_secs)` if throttled.
    pub fn check_rate_limit(&self, client_key: &str, path: &str) -> Result<(), u64> {
        let (map, policy) = if path.starts_with("/api/auth/login")
            || path.starts_with("/api/auth/change-password")
            || path.starts_with("/api/auth/webauthn")
        {
            (&self.auth_buckets, &self.auth_policy)
        } else if path.starts_with("/api/siquery/query")
            || path.starts_with("/siquery/query")
            || path.starts_with("/api/rea/")
            || path.starts_with("/rea/")
            || path.starts_with("/api/skyrl/v1/train")
            || path.starts_with("/skyrl/v1/train")
        {
            (&self.heavy_buckets, &self.heavy_policy)
        } else {
            (&self.general_buckets, &self.general_policy)
        };

        // Maintain DashMap size by evicting stale buckets if count exceeds threshold
        if map.len() > 10_000 {
            let cutoff = Instant::now() - std::time::Duration::from_secs(3600);
            map.retain(|_, v| v.last_update > cutoff);
        }

        let mut entry = map
            .entry(client_key.to_string())
            .or_insert_with(|| ClientBucket::new(policy.capacity));

        let res = entry.try_consume(policy, 1.0);
        // Strict DashMap hygiene: explicitly drop mutable entry guard immediately
        drop(entry);

        match res {
            Ok(()) => Ok(()),
            Err(wait_secs) => {
                self.total_throttled_requests
                    .fetch_add(1, Ordering::Relaxed);
                Err(wait_secs as u64)
            }
        }
    }

    /// Reset buckets for testing
    pub fn reset_all(&self) {
        self.auth_buckets.clear();
        self.heavy_buckets.clear();
        self.general_buckets.clear();
    }

    pub fn total_throttled(&self) -> u64 {
        self.total_throttled_requests.load(Ordering::Relaxed)
    }
}

impl Default for Port3030RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Global rate limiter singleton for Port 3030 daemon
pub static GLOBAL_RATE_LIMITER: Lazy<Port3030RateLimiter> = Lazy::new(Port3030RateLimiter::new);

/// Extract a normalized client identifier from request headers (IP or token)
pub fn extract_client_key(req: &Request<Body>) -> String {
    // 1. Allow explicit test client IP override for deterministic unit & integration tests
    if let Some(test_ip) = req
        .headers()
        .get("x-test-client-ip")
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = test_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    // 2. Client IP from Forwarded / X-Forwarded-For (take the first hop)
    if let Some(forwarded) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first_ip) = forwarded.split(',').next() {
            let trimmed = first_ip.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    if let Some(real_ip) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    // Default to loopback client identifier
    "127.0.0.1".to_string()
}

/// Axum middleware enforcing token-bucket rate limiting on Port 3030.
pub async fn rate_limit_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, Json<serde_json::Value>)> {
    let path = req.uri().path().to_string();

    // Health probes are strictly exempt from rate limiting to prevent false-positive liveness stalls
    if path == "/health"
        || path == "/api/health"
        || path == "/api/killchain/health-probe"
        || path == "/killchain/health-probe"
    {
        return Ok(next.run(req).await);
    }

    // Allow tests or operator bypass flag
    let bypass = req.headers().get("x-test-bypass-rate-limit").is_some()
        || std::env::var("OSOOSI_DISABLE_DASHBOARD_RATE_LIMIT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    if bypass {
        return Ok(next.run(req).await);
    }

    #[cfg(test)]
    let is_test_target = req.headers().get("x-test-client-ip").is_some();
    #[cfg(not(test))]
    let is_test_target = true;

    if !is_test_target {
        return Ok(next.run(req).await);
    }

    let client_key = extract_client_key(&req);

    match GLOBAL_RATE_LIMITER.check_rate_limit(&client_key, &path) {
        Ok(()) => Ok(next.run(req).await),
        Err(wait_secs) => {
            let error_json = json!({
                "ok": false,
                "error": "TOO_MANY_REQUESTS",
                "message": format!(
                    "Port 3030 rate limit exceeded for path '{}'. Please retry after {} seconds.",
                    path, wait_secs
                ),
                "retry_after_seconds": wait_secs,
            });

            Err((StatusCode::TOO_MANY_REQUESTS, Json(error_json)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_consumption_and_refill() {
        let policy = BucketPolicy::new(3.0, 10.0);
        let mut bucket = ClientBucket::new(3.0);

        // 3 tokens can be consumed immediately
        assert!(bucket.try_consume(&policy, 1.0).is_ok());
        assert!(bucket.try_consume(&policy, 1.0).is_ok());
        assert!(bucket.try_consume(&policy, 1.0).is_ok());

        // 4th token fails
        assert!(bucket.try_consume(&policy, 1.0).is_err());

        // Wait 150ms -> refills 1.5 tokens
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(bucket.try_consume(&policy, 1.0).is_ok());
    }

    #[test]
    fn test_rate_limiter_distinct_clients() {
        let limiter = Port3030RateLimiter::new();
        let client_a = "192.168.1.10";
        let client_b = "192.168.1.20";

        // Consume all auth tokens for client A (burst 10)
        for _ in 0..10 {
            assert!(limiter
                .check_rate_limit(client_a, "/api/auth/login")
                .is_ok());
        }
        // Client A 11th request throttled
        assert!(limiter
            .check_rate_limit(client_a, "/api/auth/login")
            .is_err());

        // Client B is unaffected
        assert!(limiter
            .check_rate_limit(client_b, "/api/auth/login")
            .is_ok());
    }
}
