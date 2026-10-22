use ipscanner::{Client, GateVerifyRequest};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(server: &MockServer) -> Client {
    Client::builder()
        .api_key("test-key")
        .base_url(server.uri())
        .build()
        .unwrap()
}

#[tokio::test]
async fn email_check_posts_with_the_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/email/check"))
        .and(header("authorization", "Bearer test-key"))
        .and(header("user-agent", "ipscanner-rust/0.3.1"))
        .and(body_json(json!({ "email": "jane@outlok.com" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "email": "jane@outlok.com", "status": "risky", "reason": "typo",
            "suggestion": "jane@outlook.com", "domain": "outlok.com",
            "checks": { "syntax": true, "mx": null, "disposable": false, "role": false, "freeProvider": false },
            "mailbox": "not_checked"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let res = client(&server)
        .email()
        .check("jane@outlok.com")
        .await
        .unwrap();
    assert_eq!(res.status, "risky");
    assert_eq!(res.reason.as_deref(), Some("typo"));
    assert_eq!(res.suggestion.as_deref(), Some("jane@outlook.com"));
    assert_eq!(res.checks.mx, None);
    assert!(res.checks.syntax);
}

#[tokio::test]
async fn gate_verify_sends_the_email() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/gate/verify"))
        .and(body_json(json!({ "secret": "gs_123", "token": "tok", "email": "x@mailinator.com" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "class": "human", "action": "block", "mode": "enforce", "confidence": 0.6,
            "network": { "classification": "residential_clean", "anonymized": false, "provider": null, "vpn_provider": null },
            "signals": [], "hostname": "example.com", "issued_at": "2026-10-14T10:00:00Z", "ip_match": true,
            "email": { "status": "risky", "reason": "disposable", "suggestion": null, "domain": "mailinator.com", "action": "block" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut req = GateVerifyRequest::new("gs_123", "tok");
    req.email = Some("x@mailinator.com".into());
    let res = client(&server).gate().verify(&req).await.unwrap();
    let email = res.email.expect("email object");
    assert_eq!(email.action, "block");
    assert_eq!(email.reason.as_deref(), Some("disposable"));
}

#[tokio::test]
async fn proxy_locked_purity_count() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/proxy/5.6.7.8"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ip": "5.6.7.8", "isProxy": false, "isTor": false, "networkClass": "hosting", "anonymized": true,
            "provider": null, "vpnProvider": null, "riskScore": 60, "purity": null, "deductionCount": 3,
            "locked": ["purity", "provider", "vpnProvider"], "planRequired": "Starter"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/vpn/1.2.3.4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ip": "1.2.3.4", "isVpn": true, "isTor": false, "networkClass": "vpn", "anonymized": true,
            "provider": "M247", "vpnProvider": "NordVPN", "riskScore": 90,
            "purity": { "score": 40, "grade": "C", "verdict": "dirty",
                        "deductions": [{ "factor": "vpn_range", "points": 30, "detail": "x" }] }
        })))
        .mount(&server)
        .await;

    let c = client(&server);
    let p = c.ip().proxy("5.6.7.8").await.unwrap();
    assert!(p.purity.is_none());
    assert_eq!(p.deduction_count, Some(3));
    let v = c.ip().vpn("1.2.3.4").await.unwrap();
    assert_eq!(v.purity.map(|p| p.deductions.len()), Some(1));
    assert_eq!(v.deduction_count, None);
}
