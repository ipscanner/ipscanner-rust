use std::time::Duration;

use ipscanner::{
    AgentCheckRequest, AgentSelfRequest, BulkRequest, Client, Error, ExportParams, HistoryParams,
    ProvenanceCheckRequest,
};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(server: &MockServer) -> Client {
    Client::builder()
        .api_key("test-key")
        .base_url(server.uri())
        .build()
        .unwrap()
}

fn keyless(server: &MockServer) -> Client {
    Client::builder().base_url(server.uri()).build().unwrap()
}

#[tokio::test]
async fn sends_auth_and_default_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vpn/1.1.1.1"))
        .and(header("authorization", "Bearer test-key"))
        .and(header("user-agent", "ipscanner-rust/0.1.0"))
        .and(header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ip": "1.1.1.1", "isVpn": false, "isTor": false, "networkClass": "hosting",
            "anonymized": false, "provider": "", "riskScore": 10
        })))
        .expect(1)
        .mount(&server)
        .await;

    let vpn = client(&server).ip().vpn("1.1.1.1").await.unwrap();
    assert_eq!(vpn.network_class, "hosting");
    assert_eq!(vpn.risk_score, 10);
}

#[tokio::test]
async fn omits_auth_without_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/myip"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ipv4": "203.0.113.7", "country": "Turkey", "countryCode": "TR", "asn": "AS9121"
        })))
        .mount(&server)
        .await;

    let me = keyless(&server).ip().myip().await.unwrap();
    assert_eq!(me.ipv4.as_deref(), Some("203.0.113.7"));
    assert_eq!(me.ipv6, None);

    let reqs = server.received_requests().await.unwrap();
    assert!(reqs[0].headers.get("authorization").is_none());
}

#[tokio::test]
async fn escapes_ipv6_path_segments() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/geo/2001%3Adb8%3A%3A1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ip": "2001:db8::1", "country": "Germany", "latitude": 52.5, "accuracyRadius": 50
        })))
        .expect(1)
        .mount(&server)
        .await;

    let geo = client(&server).ip().geo("2001:db8::1").await.unwrap();
    assert_eq!(geo.country, "Germany");
    assert_eq!(geo.accuracy_radius, 50);
}

#[tokio::test]
async fn lookup_posts_target_and_decodes_result() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/ip/lookup"))
        .and(header("content-type", "application/json"))
        .and(body_json(json!({ "target": "8.8.8.8" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "target": { "raw": "8.8.8.8", "kind": "ipv4", "ip": "8.8.8.8" },
            "reserved": { "reserved": false },
            "verdict": { "classification": "hosting", "anonymized": false, "confidence": 0.9, "method": "asn" },
            "purity": { "score": 80, "grade": "A", "verdict": "clean",
                        "deductions": [{ "factor": "hosting", "points": 20, "detail": "datacenter" }] },
            "networkClass": "hosting", "isVpn": false, "isProxy": false, "isTor": false,
            "riskScore": 20,
            "asn": { "ip": "8.8.8.8", "asn": "AS15169", "name": "Google", "type": "hosting", "country": "US" },
            "at": "2026-10-06T12:00:00.123456789Z"
        })))
        .mount(&server)
        .await;

    let r = client(&server).ip().lookup("8.8.8.8").await.unwrap();
    assert_eq!(r.target.kind, "ipv4");
    assert_eq!(r.target.hostname, None);
    assert_eq!(r.purity.deductions[0].points, 20);
    assert_eq!(r.asn.unwrap().kind, "hosting");
    assert!(r.geo.is_none());
    assert!(r.degraded.is_empty());
}

#[tokio::test]
async fn history_sends_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/ip/history"))
        .and(query_param("limit", "10"))
        .and(query_param("before", "99"))
        .and(query_param("verdict", "dirty"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "events": [{ "id": 98, "at": "2026-10-01T00:00:00Z", "target": "1.2.3.4", "ip": "1.2.3.4",
                         "verdict": "dirty", "confidence": 0.8, "asn": "AS1", "asnName": "X",
                         "country": "US", "anonymized": true, "source": "api" }],
            "nextBefore": 0, "asOf": "2026-10-06T00:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let h = client(&server)
        .ip()
        .history(&HistoryParams {
            limit: Some(10),
            before: Some(99),
            verdict: Some("dirty".into()),
        })
        .await
        .unwrap();
    assert_eq!(h.events[0].asn_name, "X");
    assert_eq!(h.next_before, 0);
}

#[tokio::test]
async fn agentscan_check_sends_snake_case() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agentscan/check"))
        .and(body_json(json!({
            "ip": "1.2.3.4",
            "user_agent": "curl/8",
            "headless_flags": { "webdriver": true },
            "request_id": "r1"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "class": "malicious_automation", "confidence": 0.7, "action": "block",
            "signals": { "network_origin": "hosting", "headless": true }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let req = AgentCheckRequest {
        user_agent: Some("curl/8".into()),
        headless_flags: Some([("webdriver".to_string(), true)].into()),
        request_id: Some("r1".into()),
        ..AgentCheckRequest::new("1.2.3.4")
    };
    let res = client(&server).agentscan().check(&req).await.unwrap();
    assert_eq!(res.action, "block");
    assert_eq!(res.signals["network_origin"], "hosting");
}

#[tokio::test]
async fn agentscan_self_check_sends_empty_object() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agentscan/self"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ip": "1.2.3.4", "userAgent": "", "ja4": "", "ja4Source": "unavailable",
            "class": "human", "confidence": 0.5, "action": "allow", "signals": {},
            "metered": false, "asOf": "2026-10-06T00:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let res = client(&server)
        .agentscan()
        .self_check(&AgentSelfRequest::default())
        .await
        .unwrap();
    assert_eq!(res.ja4_source, "unavailable");
    assert!(res.asn.is_none());
}

#[tokio::test]
async fn provenance_check_round_trips_snake_case() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/provenance/check"))
        .and(body_json(json!({
            "ip": "1.2.3.4",
            "claimed_jurisdiction": "EU",
            "request_context": { "orderId": 7 }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "network_origin": "residential_clean", "anonymized": false, "method": "asn",
            "confidence": 0.95, "policy_action": "allow", "attestation_id": 42
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut ctx = serde_json::Map::new();
    ctx.insert("orderId".into(), json!(7));
    let req = ProvenanceCheckRequest {
        claimed_jurisdiction: Some("EU".into()),
        request_context: Some(ctx),
        ..ProvenanceCheckRequest::new("1.2.3.4")
    };
    let res = client(&server).provenance().check(&req).await.unwrap();
    assert_eq!(res.policy_action, "allow");
    assert_eq!(res.attestation_id, 42);
}

#[tokio::test]
async fn provenance_export_returns_csv() {
    let server = MockServer::start().await;
    let csv = "# provenance evidence export\nid,ts,ip\n1,2026-10-01T00:00:00Z,1.2.3.4\n";
    Mock::given(method("GET"))
        .and(path("/v1/provenance/export"))
        .and(query_param("from", "2026-10-01"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(csv, "text/csv"))
        .mount(&server)
        .await;

    let out = client(&server)
        .provenance()
        .export(&ExportParams {
            from: Some("2026-10-01".into()),
            to: None,
        })
        .await
        .unwrap();
    assert_eq!(out, csv);
}

#[tokio::test]
async fn asn_directory_get_strips_prefix() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/asn/directory/15169"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "asn": 15169, "label": "AS15169", "org": "Google", "networkType": "hosting",
            "ipv4Prefixes": 10, "ipv6Prefixes": 5, "prefixes": 15, "addresses": 9000000,
            "samplePrefixes": [{ "prefix": "8.8.8.0/24", "version": 4, "addresses": 256 },
                               { "prefix": "2001:4860::/32", "version": 6 }],
            "vpnRangePrefixes": 0, "datacenterRangePrefixes": 3, "rangesLoaded": true
        })))
        .expect(2)
        .mount(&server)
        .await;

    let c = keyless(&server);
    let a = c.asn_directory().get("AS15169").await.unwrap();
    let b = c.asn_directory().get(15169).await.unwrap();
    assert_eq!(a, b);
    assert_eq!(a.sample_prefixes[1].addresses, None);
}

#[tokio::test]
async fn maps_authentication_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_api_key", "message": "Invalid API key"
        })))
        .mount(&server)
        .await;

    let err = client(&server).account().limits().await.unwrap_err();
    match &err {
        Error::Authentication(e) => {
            assert_eq!(e.status, 401);
            assert_eq!(e.code, "invalid_api_key");
            assert_eq!(e.message, "Invalid API key");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(err.code(), Some("invalid_api_key"));
}

#[tokio::test]
async fn maps_not_found_and_bad_request_details() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/asn/directory/1"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "not_found", "message": "No autonomous system"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/bulk/check"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "bad_request", "message": "Hostnames are not accepted",
            "details": { "invalid": ["example.com"] }
        })))
        .mount(&server)
        .await;

    let c = client(&server);
    assert!(matches!(
        c.asn_directory().get(1).await,
        Err(Error::NotFound(_))
    ));

    let err = c
        .bulk()
        .check(&BulkRequest::ips(["example.com"]))
        .await
        .unwrap_err();
    let Error::Api(e) = err else {
        panic!("expected Api error")
    };
    assert_eq!(e.status, 400);
    assert_eq!(e.details.unwrap()["invalid"][0], "example.com");
}

#[tokio::test]
async fn maps_non_json_error_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_string("<html>oops</html>"))
        .expect(1)
        .mount(&server)
        .await;

    let err = client(&server).crawlers().list().await.unwrap_err();
    let Error::Api(e) = err else {
        panic!("expected Api error")
    };
    assert_eq!(e.code, "http_500");
    assert_eq!(e.message, "Internal Server Error");
    assert_eq!(e.body, "<html>oops</html>");
}

#[tokio::test]
async fn maps_quota_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/ip/lookup"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "999")
                .insert_header("X-RateLimit-Limit", "30000")
                .insert_header("X-RateLimit-Remaining", "0")
                .insert_header("X-RateLimit-Meter", "request")
                .insert_header("X-RateLimit-Usage-Percent", "100")
                .set_body_json(json!({
                    "error": "rate_limit_exceeded", "reason": "monthly_quota",
                    "message": "Monthly quota reached", "meter": "request", "plan": "Free",
                    "limit": 30000, "usage": 30000, "remaining": 0,
                    "resetDate": "2026-11-01", "resetAt": "2026-11-01T00:00:00Z",
                    "retryAfter": 60, "softBlock": true,
                    "upgrade": { "recommendedPlan": "Starter", "url": "https://ipscanner.io/pricing", "message": "Upgrade" }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let err = client(&server).ip().lookup("1.1.1.1").await.unwrap_err();
    assert_eq!(err.status(), Some(429));
    let Error::RateLimit(e) = err else {
        panic!("expected RateLimit")
    };
    assert_eq!(e.api.code, "rate_limit_exceeded");
    assert_eq!(e.reason.as_deref(), Some("monthly_quota"));
    assert_eq!(e.retry_after, Some(Duration::from_secs(60)));
    assert_eq!(e.reset_at.as_deref(), Some("2026-11-01T00:00:00Z"));
    assert_eq!(e.limit, Some(30000));
    assert_eq!(e.remaining, Some(0));
    assert_eq!(e.needed, None);
    assert_eq!(e.plan.as_deref(), Some("Free"));
    assert_eq!(
        e.upgrade_url.as_deref(),
        Some("https://ipscanner.io/pricing")
    );
    assert_eq!(e.rate_limit.limit, Some(30000));
    assert_eq!(e.rate_limit.meter.as_deref(), Some("request"));
    assert_eq!(e.rate_limit.usage_percent, Some(100.0));
    assert_eq!(e.rate_limit.retry_after, Some(999));
}

#[tokio::test]
async fn rate_limit_falls_back_to_retry_after_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "30")
                .set_body_json(json!({ "error": "rate_limit_exceeded", "message": "Slow down" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let err = keyless(&server).ip().demo("1.1.1.1").await.unwrap_err();
    let Error::RateLimit(e) = err else {
        panic!("expected RateLimit")
    };
    assert_eq!(e.retry_after, Some(Duration::from_secs(30)));
    assert_eq!(e.reason, None);
}

#[tokio::test]
async fn retries_get_on_503() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/usage/summary"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/usage/summary"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "plan": "Pro", "used": 10, "limit": 500000, "unlimited": false, "remaining": 499990,
            "percent": 0.002, "softBlocked": false, "blockedBy": "", "upgradeHint": false,
            "bulkCap": 1000, "daily": null,
            "hourly": { "limit": 5000, "used": 1, "remaining": 4999, "resetAt": "2026-10-06T13:00:00Z" },
            "periodStart": "2026-10-01", "resetDate": "2026-11-01", "asOf": "2026-10-06T12:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let usage = client(&server).account().usage().await.unwrap();
    assert_eq!(usage.plan, "Pro");
    assert!(usage.daily.is_none());
    assert_eq!(usage.hourly.unwrap().remaining, 4999);
}

#[tokio::test]
async fn gives_up_after_max_retries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(502))
        .expect(2)
        .mount(&server)
        .await;

    let c = Client::builder()
        .base_url(server.uri())
        .max_retries(1)
        .build()
        .unwrap();
    let err = c.crawlers().list().await.unwrap_err();
    assert_eq!(err.code(), Some("http_502"));
}

#[tokio::test]
async fn does_not_retry_post_or_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429))
        .expect(1)
        .mount(&server)
        .await;

    let c = client(&server);
    assert_eq!(
        c.ip().lookup("1.1.1.1").await.unwrap_err().status(),
        Some(503)
    );
    assert!(matches!(
        c.ip().vpn("1.1.1.1").await,
        Err(Error::RateLimit(_))
    ));
}

#[tokio::test]
async fn times_out() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(500)))
        .mount(&server)
        .await;

    let c = Client::builder()
        .base_url(server.uri())
        .timeout(Duration::from_millis(50))
        .max_retries(0)
        .build()
        .unwrap();
    assert!(matches!(c.ip().myip().await, Err(Error::Timeout)));
}
