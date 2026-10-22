use std::time::Duration;

use futures_util::StreamExt;
use ipscanner::{BulkEvent, BulkRequest, Client, Error};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const NDJSON: &str = concat!(
    r#"{"type":"meta","total":3,"processed":1,"failed":1,"metered":3}"#,
    "\n",
    r#"{"type":"result","input":"1.1.1.1","ip":"1.1.1.1","verdict":"suspect","classification":"hosting","confidence":0.9,"score":55,"grade":"B","asn":"AS13335"}"#,
    "\n",
    r#"{"type":"error","index":1,"input":"10.0.0.1","reason":"reserved","message":"Private range"}"#,
    "\r\n\n",
    r#"{"type":"result","index":2,"ip":"8.8.8.8","anonymized":true,"isTorExit":true}"#,
    "\n",
    r#"{"type":"done","reason":"complete","processed":2,"failed":1,"total":3}"#,
);

fn client(uri: String) -> Client {
    Client::builder()
        .api_key("test-key")
        .base_url(uri)
        .build()
        .unwrap()
}

async fn collect(c: &Client, req: &BulkRequest) -> Vec<BulkEvent> {
    let stream = c.bulk().stream(req).await.unwrap();
    stream.map(|e| e.unwrap()).collect().await
}

#[tokio::test]
async fn parses_ndjson_stream() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/ip/bulk"))
        .and(header("content-type", "application/json"))
        .and(body_json(
            json!({ "ips": ["1.1.1.1", "10.0.0.1", "8.8.8.8"] }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(NDJSON, "application/x-ndjson"))
        .expect(1)
        .mount(&server)
        .await;

    let events = collect(
        &client(server.uri()),
        &BulkRequest::ips(["1.1.1.1", "10.0.0.1", "8.8.8.8"]),
    )
    .await;

    assert_eq!(events.len(), 5);
    assert_eq!(events[0].kind, "meta");
    assert_eq!(events[0].metered, 3);
    assert_eq!(events[1].kind, "result");
    assert_eq!(events[1].index, 0);
    assert_eq!(events[1].score, 55);
    assert!(!events[1].anonymized);
    assert_eq!(events[2].reason, "reserved");
    assert!(events[3].is_tor_exit);
    assert_eq!(events[4].kind, "done");
    assert!(events[4].complete());
}

#[tokio::test]
async fn parses_locked_stream_lines() {
    let body = concat!(
        r#"{"type":"meta","total":2,"metered":2,"planRequired":"Starter"}"#,
        "\n",
        r#"{"type":"result","ip":"185.65.135.1","classification":"vpn","anonymized":true,"score":null,"grade":null,"verdict":null,"vpnProvider":null,"locked":["score","grade","verdict","vpnProvider"]}"#,
        "\n",
        r#"{"type":"result","index":1,"ip":"185.65.135.2","verdict":"dirty","score":10,"grade":"C","vpnProvider":"Mullvad"}"#,
        "\n",
        r#"{"type":"done","reason":"complete","processed":2,"total":2}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/ip/bulk"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/x-ndjson"))
        .mount(&server)
        .await;

    let events = collect(
        &client(server.uri()),
        &BulkRequest::ips(["185.65.135.1", "185.65.135.2"]),
    )
    .await;

    assert_eq!(events[0].plan_required, "Starter");
    assert_eq!(events[1].score, 0);
    assert_eq!(events[1].grade, "");
    assert_eq!(events[1].vpn_provider, "");
    assert_eq!(
        events[1].locked,
        ["score", "grade", "verdict", "vpnProvider"]
    );
    assert_eq!(events[2].vpn_provider, "Mullvad");
    assert_eq!(events[2].score, 10);
    assert!(events[2].locked.is_empty());
    assert!(events[3].complete());
}

#[tokio::test]
async fn done_with_missing_rows_is_not_complete() {
    let ev: BulkEvent = serde_json::from_value(json!({
        "type": "done", "reason": "complete", "processed": 2, "total": 5
    }))
    .unwrap();
    assert!(!ev.complete());

    let ev: BulkEvent = serde_json::from_value(json!({
        "type": "done", "reason": "quota_exceeded", "processed": 5, "total": 5
    }))
    .unwrap();
    assert!(!ev.complete());
}

#[tokio::test]
async fn pre_stream_errors_are_returned() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/ip/bulk"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": "rate_limit_exceeded", "reason": "insufficient_for_batch",
            "message": "Not enough quota", "needed": 500, "remaining": 20, "retryAfter": 3600
        })))
        .mount(&server)
        .await;

    let err = client(server.uri())
        .bulk()
        .stream(&BulkRequest::input("1.1.1.1\n8.8.8.8"))
        .await
        .unwrap_err();
    let Error::RateLimit(e) = err else {
        panic!("expected RateLimit")
    };
    assert_eq!(e.needed, Some(500));
    assert_eq!(e.retry_after, Some(Duration::from_secs(3600)));
}

#[tokio::test]
async fn handles_chunks_split_mid_line() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let mut req = Vec::new();
        loop {
            let n = sock.read(&mut buf).await.unwrap();
            req.extend_from_slice(&buf[..n]);
            if let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&req[..end]).to_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse().unwrap())
                    .unwrap_or(0);
                if req.len() >= end + 4 + len {
                    break;
                }
            }
        }

        sock.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .await
        .unwrap();
        let body = NDJSON.as_bytes();
        let cuts = [10, 75, 76, 200, body.len()];
        let mut start = 0;
        for end in cuts {
            let chunk = &body[start..end];
            sock.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            sock.write_all(chunk).await.unwrap();
            sock.write_all(b"\r\n").await.unwrap();
            sock.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            start = end;
        }
        sock.write_all(b"0\r\n\r\n").await.unwrap();
        sock.flush().await.unwrap();
    });

    let events = collect(
        &client(format!("http://{addr}")),
        &BulkRequest::ips(["1.1.1.1"]),
    )
    .await;

    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["meta", "result", "error", "result", "done"]);
    assert_eq!(events[1].asn, "AS13335");
    assert_eq!(events[3].index, 2);
    assert!(events[4].complete());
}

#[test]
fn complete_does_not_overflow() {
    let done = |processed, failed, total| BulkEvent {
        kind: "done".into(),
        reason: "complete".into(),
        processed,
        failed,
        total,
        ..Default::default()
    };
    assert!(done(i64::MAX, 1, i64::MAX).complete());
    assert!(!done(i64::MIN, -1, i64::MIN).complete());
}
