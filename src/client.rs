use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::{Method, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{self, Error};
use crate::resources::{
    Account, Agentscan, AsnDirectory, Bulk, Crawlers, Edge, Email, Gate, Ip, Provenance, Sites,
};

/// The default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://ipscanner.io";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_RETRIES: u32 = 2;
const USER_AGENT_VALUE: &str = concat!("ipscanner-rust/", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Copy)]
struct Opts<'a> {
    accept: &'a str,
    timeout: Option<Duration>,
    auth: bool,
}

const JSON: Opts<'static> = Opts {
    accept: "application/json",
    timeout: None,
    auth: true,
};

/// An IPScanner API client. Cheap to clone; clones share one connection pool.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    timeout: Duration,
    max_retries: u32,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.inner.base_url)
            .field(
                "api_key",
                &self.inner.api_key.as_ref().map(|_| "[redacted]"),
            )
            .field("timeout", &self.inner.timeout)
            .field("max_retries", &self.inner.max_retries)
            .finish()
    }
}

impl Client {
    /// Creates a client with the given API key. Panics if the TLS backend fails, like `reqwest::Client::new`.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::builder()
            .api_key(api_key)
            .build()
            .expect("failed to build HTTP client")
    }

    /// Creates a client from `IPSCANNER_API_KEY` and `IPSCANNER_API_URL`; without a key only keyless routes work.
    pub fn from_env() -> Self {
        let mut b = Self::builder();
        if let Ok(key) = std::env::var("IPSCANNER_API_KEY") {
            b = b.api_key(key);
        }
        if let Ok(url) = std::env::var("IPSCANNER_API_URL") {
            if !url.trim().is_empty() {
                b = b.base_url(url);
            }
        }
        b.build().expect("failed to build HTTP client")
    }

    /// Returns a builder for a client with custom settings.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// IP lookups, single-signal checks and lookup history.
    pub fn ip(&self) -> Ip<'_> {
        Ip::new(self)
    }

    /// Bulk checks, as one JSON response or as an NDJSON stream.
    pub fn bulk(&self) -> Bulk<'_> {
        Bulk::new(self)
    }

    /// Agentscan: classify requests as human, bot, AI agent or automation.
    pub fn agentscan(&self) -> Agentscan<'_> {
        Agentscan::new(self)
    }

    /// Provenance attestations and the evidence chain.
    pub fn provenance(&self) -> Provenance<'_> {
        Provenance::new(self)
    }

    /// Plan limits and usage.
    pub fn account(&self) -> Account<'_> {
        Account::new(self)
    }

    /// The public ASN directory.
    pub fn asn_directory(&self) -> AsnDirectory<'_> {
        AsnDirectory::new(self)
    }

    /// The catalogue of verifiable crawlers.
    pub fn crawlers(&self) -> Crawlers<'_> {
        Crawlers::new(self)
    }

    /// Edge checks: Agentscan and the network check for one visitor.
    pub fn edge(&self) -> Edge<'_> {
        Edge::new(self)
    }

    /// Site policies for Workers.
    pub fn sites(&self) -> Sites<'_> {
        Sites::new(self)
    }

    /// The form gate's server-side token verification.
    pub fn gate(&self) -> Gate<'_> {
        Gate::new(self)
    }

    /// Email address checks.
    pub fn email(&self) -> Email<'_> {
        Email::new(self)
    }

    pub(crate) async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, Error> {
        let res = self.send(Method::GET, path, query, None, JSON).await?;
        decode(res).await
    }

    pub(crate) async fn post<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let res = self.post_raw(path, body, None).await?;
        decode(res).await
    }

    pub(crate) async fn post_raw<B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let body = serde_json::to_vec(body)?;
        self.send(
            Method::POST,
            path,
            &[],
            Some(body),
            Opts { timeout, ..JSON },
        )
        .await
    }

    pub(crate) async fn post_keyless<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let body = serde_json::to_vec(body)?;
        let opts = Opts {
            auth: false,
            ..JSON
        };
        let res = self.send(Method::POST, path, &[], Some(body), opts).await?;
        decode(res).await
    }

    pub(crate) async fn get_text(
        &self,
        path: &str,
        query: &[(&str, String)],
        accept: &str,
    ) -> Result<String, Error> {
        let res = self
            .send(Method::GET, path, query, None, Opts { accept, ..JSON })
            .await?;
        Ok(res.text().await?)
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Vec<u8>>,
        opts: Opts<'_>,
    ) -> Result<Response, Error> {
        let inner = &self.inner;
        let url = format!("{}/v1{}", inner.base_url, path);
        let retries = if method == Method::GET {
            inner.max_retries
        } else {
            0
        };
        let mut attempt = 0;
        loop {
            let mut req = inner
                .http
                .request(method.clone(), &url)
                .timeout(opts.timeout.unwrap_or(inner.timeout))
                .header(USER_AGENT, USER_AGENT_VALUE)
                .header(ACCEPT, opts.accept);
            if !query.is_empty() {
                req = req.query(query);
            }
            if let Some(key) = inner.api_key.as_ref().filter(|_| opts.auth) {
                req = req.header(AUTHORIZATION, format!("Bearer {key}"));
            }
            if let Some(b) = &body {
                req = req
                    .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                    .body(b.clone());
            }

            match req.send().await {
                Ok(res) => {
                    let status = res.status();
                    if status.is_success() {
                        return Ok(res);
                    }
                    if attempt < retries && matches!(status.as_u16(), 502..=504) {
                        backoff(attempt).await;
                        attempt += 1;
                        continue;
                    }
                    let headers = res.headers().clone();
                    let text = res.text().await.unwrap_or_default();
                    return Err(error::from_response(status, &headers, text));
                }
                Err(e) => {
                    if attempt < retries && !e.is_builder() {
                        backoff(attempt).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }
    }
}

async fn backoff(attempt: u32) {
    tokio::time::sleep(Duration::from_millis(500 << attempt)).await;
}

async fn decode<T: DeserializeOwned>(res: Response) -> Result<T, Error> {
    let bytes = res.bytes().await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Percent-encodes a single path segment.
pub(crate) fn segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Builds a [`Client`] with custom settings.
#[derive(Default)]
pub struct ClientBuilder {
    api_key: Option<String>,
    base_url: Option<String>,
    timeout: Option<Duration>,
    max_retries: Option<u32>,
    http_client: Option<reqwest::Client>,
}

impl ClientBuilder {
    /// Sets the API key sent as a bearer token.
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Overrides the base URL. Defaults to `https://ipscanner.io`.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Sets the per-request timeout. Defaults to 30 seconds. Bulk streams use 5 minutes.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets how many times a failed GET is retried. Defaults to 2.
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = Some(n);
        self
    }

    /// Uses an existing `reqwest::Client`.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Builds the client.
    pub fn build(self) -> Result<Client, Error> {
        let http = match self.http_client {
            Some(c) => c,
            None => reqwest::Client::builder().build()?,
        };
        let base_url = self
            .base_url
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        let api_key = self
            .api_key
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty());
        Ok(Client {
            inner: Arc::new(Inner {
                http,
                base_url,
                api_key,
                timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
                max_retries: self.max_retries.unwrap_or(DEFAULT_MAX_RETRIES),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::segment;

    #[test]
    fn escapes_ipv6() {
        assert_eq!(segment("2001:db8::1"), "2001%3Adb8%3A%3A1");
        assert_eq!(segment("1.1.1.1"), "1.1.1.1");
        assert_eq!(segment("a/b"), "a%2Fb");
    }
}
