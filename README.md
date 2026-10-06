# ipscanner-rust

Official Rust client for the [IPScanner](https://ipscanner.io) API.

## Install

```sh
cargo add ipscanner-io
```

The crate is imported as `ipscanner`. It is async and runs on Tokio.

## Quick start

```rust
#[tokio::main]
async fn main() -> Result<(), ipscanner::Error> {
    let client = ipscanner::Client::new("pk_live_...");

    let result = client.ip().lookup("1.1.1.1").await?;
    println!("{} {} {}", result.target.ip, result.network_class, result.purity.grade);
    Ok(())
}
```

Get a key at https://ipscanner.io. Full API reference: https://ipscanner.io/api-documentation.

## Usage

### IP

```rust
use ipscanner::HistoryParams;

let result = client.ip().lookup("example.com").await?;
let vpn = client.ip().vpn("2001:db8::1").await?;
let proxy = client.ip().proxy("1.1.1.1").await?;
let geo = client.ip().geo("1.1.1.1").await?;
let asn = client.ip().asn("1.1.1.1").await?;
let whois = client.ip().whois("example.com").await?;
let history = client.ip().history(&HistoryParams { limit: Some(50), ..Default::default() }).await?;
let demo = client.ip().demo("8.8.8.8").await?;
let me = client.ip().myip().await?;
```

`demo` and `myip` work without a key.

### Bulk

```rust
use futures_util::StreamExt;
use ipscanner::BulkRequest;

let report = client.bulk().check(&BulkRequest::ips(["1.1.1.1", "8.8.8.8"])).await?;

let mut stream = client.bulk().stream(&BulkRequest::input("1.1.1.1\n8.8.8.8")).await?;
while let Some(event) = stream.next().await {
    let event = event?;
    match event.kind.as_str() {
        "result" => println!("{} {}", event.ip, event.verdict),
        "done" if !event.complete() => println!("stopped early: {}", event.reason),
        _ => {}
    }
}
```

The stream reads NDJSON with a 5 minute timeout. `BulkEvent::complete()` is true only when every unique IP was processed.

### Agentscan

```rust
use ipscanner::{AgentBatchLine, AgentCheckRequest, AgentSelfRequest, CrawlerVerifyRequest};

let check = client.agentscan().check(&AgentCheckRequest {
    user_agent: Some("Mozilla/5.0".into()),
    ..AgentCheckRequest::new("203.0.113.7")
}).await?;

let batch = client.agentscan().batch(&[AgentBatchLine::new(1, "203.0.113.7")]).await?;
let verified = client.agentscan().verify(&CrawlerVerifyRequest::bot("66.249.66.1", "googlebot")).await?;
let allowlist = client.agentscan().allowlist().await?;
let me = client.agentscan().self_check(&AgentSelfRequest::default()).await?;
```

### Provenance

```rust
use ipscanner::{ChainParams, ExportParams, ProvenanceCheckRequest};

let attestation = client.provenance().check(&ProvenanceCheckRequest {
    claimed_jurisdiction: Some("EU".into()),
    ..ProvenanceCheckRequest::new("203.0.113.7")
}).await?;

let chain = client.provenance().chain(&ChainParams { limit: Some(100), ..Default::default() }).await?;
let ok = client.provenance().verify().await?;
let anchored = client.provenance().verify_anchored().await?;
let jurisdictions = client.provenance().jurisdictions().await?;
let csv: String = client.provenance().export(&ExportParams {
    from: Some("2026-01-01".into()),
    ..Default::default()
}).await?;
```

### Account

```rust
let limits = client.account().limits().await?;
let usage = client.account().usage().await?;
```

### ASN directory

```rust
use ipscanner::AsnTopParams;

let top = client.asn_directory().top(&AsnTopParams { top: Some(20), ..Default::default() }).await?;
let found = client.asn_directory().search("cloudflare", Some(10)).await?;
let google = client.asn_directory().get("AS15169").await?;
```

### Crawlers

```rust
let crawlers = client.crawlers().list().await?;
```

## Errors

Every call returns `Result<T, ipscanner::Error>`:

| Variant | When |
| --- | --- |
| `Error::Authentication(ApiError)` | 401 or 403 |
| `Error::NotFound(ApiError)` | 404 |
| `Error::RateLimit(Box<RateLimitError>)` | 429 |
| `Error::Api(ApiError)` | any other error status |
| `Error::Timeout` | the request timed out |
| `Error::Http(reqwest::Error)` | connection or transport failure |
| `Error::Decode(serde_json::Error)` | unexpected response body |

`ApiError` has `status`, `code`, `message`, `details` and the raw `body`. `RateLimitError` adds `reason`, `retry_after`, `reset_at`, `limit`, `usage`, `remaining`, `needed`, `plan`, `upgrade_url` and the parsed `X-RateLimit-*` headers.

```rust
match client.ip().lookup("1.1.1.1").await {
    Ok(result) => println!("{}", result.network_class),
    Err(ipscanner::Error::RateLimit(e)) => println!("retry in {:?}", e.retry_after),
    Err(e) => println!("{e}"),
}
```

GET requests are retried up to 2 times on connection errors and 502, 503 and 504. POST requests and 429 responses are never retried.

## Configuration

```rust
use std::time::Duration;

let client = ipscanner::Client::builder()
    .api_key("pk_live_...")
    .base_url("https://ipscanner.io")
    .timeout(Duration::from_secs(10))
    .max_retries(3)
    .build()?;
```

`Client::from_env()` reads `IPSCANNER_API_KEY` and `IPSCANNER_API_URL`. A client without a key can call the keyless routes. Pass your own `reqwest::Client` with `.http_client(..)`.

## Licence

MIT
