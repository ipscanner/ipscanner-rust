//! Official Rust client for the [IPScanner](https://ipscanner.io) API.
//!
//! ```no_run
//! # async fn run() -> Result<(), ipscanner::Error> {
//! let client = ipscanner::Client::new("pk_live_...");
//!
//! let result = client.ip().lookup("1.1.1.1").await?;
//! println!("{} {}", result.network_class, result.risk_score);
//!
//! let vpn = client.ip().vpn("2001:4860:4860::8888").await?;
//! println!("vpn: {}", vpn.is_vpn);
//! # Ok(())
//! # }
//! ```
//!
//! See <https://ipscanner.io/api-documentation> for the full API reference.

#![forbid(unsafe_code)]

mod client;
mod error;
pub mod resources;
pub mod types;

pub use client::{Client, ClientBuilder, DEFAULT_BASE_URL};
pub use error::{ApiError, Error, RateLimitError, RateLimitHeaders};
pub use resources::BulkStream;
pub use types::*;
