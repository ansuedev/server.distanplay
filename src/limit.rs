//! Tiny in-memory rate limit per IP and endpoint (fixed one-minute windows). Enough
//! for one instance; use Redis or the proxy's limits if this ever runs on several.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::error::{ApiError, ApiResult};

#[derive(Default)]
pub struct Limiter {
    windows: DashMap<(&'static str, IpAddr), (Instant, u32)>,
}

impl Limiter {
    /// Allows `per_minute` calls of `what` per IP.
    pub fn check(&self, what: &'static str, ip: IpAddr, per_minute: u32) -> ApiResult<()> {
        let mut e = self.windows.entry((what, ip)).or_insert((Instant::now(), 0));
        if e.0.elapsed() >= Duration::from_secs(60) {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        if e.1 > per_minute { Err(ApiError::TooMany) } else { Ok(()) }
    }

    pub fn prune(&self) {
        self.windows.retain(|_, v| v.0.elapsed() < Duration::from_secs(120));
    }
}
