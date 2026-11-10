use base64::Engine;
use xmsg_mcp_gateway::webhook::{self, Error, PublicHttps, Transport};

fn secret(byte: u8) -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    )
}

#[test]
fn standard_vector_dual_signatures_and_tampering() {
    let body = br#"{"email":"test@example.com","username":"test_user"}"#;
    let old = "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD";
    let new = secret(8);
    let headers = webhook::signed_headers(
        "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk",
        "sub_owned",
        1649367553,
        body,
        old,
        Some(&new),
    )
    .unwrap();
    assert!(headers["webhook-signature"]
        .to_str()
        .unwrap()
        .starts_with("v1,tZ1I4/hDygAJgO5TYxiSd6Sd0kDW6hPenDe+bTa3Kkw= "));
    let timestamp = webhook::signing_time().unwrap();
    let headers =
        webhook::signed_headers("event", "sub_owned", timestamp, body, old, Some(&new)).unwrap();
    for key in [old, &new] {
        let fixture = standardwebhooks::Webhook::new(key).unwrap();
        fixture.verify(body, &headers).unwrap();
        assert!(fixture.verify(b"tampered", &headers).is_err());
    }
    assert!(standardwebhooks::Webhook::new(&secret(9))
        .unwrap()
        .verify(body, &headers)
        .is_err());
    assert_eq!(headers["webhook-id"], "event");
    assert_eq!(headers["x-mcp-subscription-id"], "sub_owned");
    assert!(!format!("{:?}", webhook::validate_secret(old).unwrap()).contains(old));
}

#[test]
fn secret_and_header_bounds() {
    for bytes in [23, 65] {
        let key = format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode(vec![4; bytes])
        );
        assert!(webhook::validate_secret(&key).is_err());
    }
    for bytes in [24, 64] {
        let key = format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode(vec![4; bytes])
        );
        assert!(webhook::validate_secret(&key).is_ok());
    }
    assert!(webhook::validate_secret("C2FVsBQIhrscChlQIMV+b5sSYspob7oD").is_err());
    assert!(
        webhook::signed_headers("event\r\nInjected:yes", "sub", 1, b"{}", &secret(1), None)
            .is_err()
    );
}

#[tokio::test]
async fn public_transport_rejects_private_and_malformed_callbacks_before_connect() {
    for url in [
        "http://8.8.8.8/",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://100.64.0.1/",
        "https://100.127.255.255/",
        "https://100.100.100.100/",
        "https://[fec0::1]/",
        "https://[::ffff:8.8.8.8]/",
        "https://[2002:0808:0808::1]/",
        "https://user@8.8.8.8/",
        "https://@8.8.8.8/",
        "https://8.8.8.8/#fragment",
        "https://8.8.8.8/\n",
    ] {
        let result = PublicHttps
            .post(url, reqwest::header::HeaderMap::new(), b"{}".to_vec())
            .await;
        assert!(
            matches!(result, Err(Error::Destination)),
            "{url}: {result:?}"
        );
    }
}

struct CallbackFixture {
    mode: &'static str,
}
impl Transport for CallbackFixture {
    fn post<'a>(
        &'a self,
        _url: &'a str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> webhook::PostFuture<'a> {
        Box::pin(async move {
            standardwebhooks::Webhook::new(&secret(2))
                .unwrap()
                .verify(&body, &headers)
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["type"], "verification");
            assert_eq!(headers["x-mcp-subscription-id"], "owned");
            let (status, body) = match self.mode {
                "refused" => (403, b"not authorized".to_vec()),
                "invalid-json" => (200, b"not json".to_vec()),
                "wrong-echo" => (200, br#"{"challenge":"wrong"}"#.to_vec()),
                "oversize" => (200, vec![b' '; webhook::MAX_RESPONSE_BYTES + 1]),
                _ => (
                    200,
                    serde_json::to_vec(&serde_json::json!({"challenge":value["challenge"]}))
                        .unwrap(),
                ),
            };
            Ok(webhook::Response {
                status,
                body,
                retry_after: None,
            })
        })
    }
}

#[tokio::test]
async fn challenge_is_signed_echoed_and_failure_is_content_free() {
    for mode in ["ok", "refused", "invalid-json", "wrong-echo", "oversize"] {
        let result = webhook::verify_callback(
            &CallbackFixture { mode },
            "https://callback.example/private?secret=hidden",
            "owned",
            &secret(2),
        )
        .await;
        assert_eq!(result.is_ok(), mode == "ok");
        if let Err(error) = result {
            assert_eq!(error, Error::Challenge);
            assert!(!format!("{error:?}").contains("hidden"));
        }
    }
}

struct Never;
impl Transport for Never {
    fn post<'a>(
        &'a self,
        _url: &'a str,
        _headers: reqwest::header::HeaderMap,
        _body: Vec<u8>,
    ) -> webhook::PostFuture<'a> {
        Box::pin(std::future::pending())
    }
}
#[tokio::test(start_paused = true)]
async fn injected_transport_cannot_escape_total_callback_budget() {
    let result =
        webhook::verify_callback(&Never, "https://callback.example/", "owned", &secret(2)).await;
    assert_eq!(result, Err(Error::Timeout));
}

#[test]
fn callback_address_matrix() {
    for raw in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.0",
        "100.127.255.255",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::8.8.8.8",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "64:ff9b:1::1",
        "100::1",
        "2001::1",
        "2001:db8::1",
        "2001:20::1",
        "2002::1",
        "3fff::1",
        "fc00::1",
        "fe80::1",
        "fec0::1",
        "ff00::1",
    ] {
        assert!(!webhook::public_address(raw.parse().unwrap()), "{raw}");
    }
    for raw in [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ] {
        assert!(webhook::public_address(raw.parse().unwrap()), "{raw}");
    }
}

#[test]
fn retry_after_accepts_seconds_and_http_dates_without_unbounded_values() {
    let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    assert_eq!(webhook::retry_after_seconds("120", now), Some(120));
    assert_eq!(webhook::retry_after_seconds("invalid", now), None);
    assert_eq!(webhook::retry_after_seconds(&"1".repeat(129), now), None);
    let future = httpdate::fmt_http_date(now + std::time::Duration::from_secs(240));
    assert_eq!(webhook::retry_after_seconds(&future, now), Some(240));
    let past = httpdate::fmt_http_date(now - std::time::Duration::from_secs(5));
    assert_eq!(webhook::retry_after_seconds(&past, now), Some(0));
}
