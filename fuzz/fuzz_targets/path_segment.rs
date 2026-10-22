#![no_main]

use ipscanner::fuzzing::segment;
use libfuzzer_sys::fuzz_target;
use reqwest::Url;

fn unhex(b: u8) -> u8 {
    (b as char).to_digit(16).expect("hex digit") as u8
}

fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(unhex(b[i + 1]) << 4 | unhex(b[i + 2]));
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

fuzz_target!(|s: &str| {
    let seg = segment(s);
    assert!(seg
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._~%".contains(&b)));

    // The request must stay on the route it was built for.
    let path = format!("/v1/vpn/{seg}");
    let url = Url::parse(&format!("https://ipscanner.io{path}")).unwrap();
    assert_eq!(url.path(), path, "input {s:?}");
    assert_eq!(url.path_segments().unwrap().count(), 3, "input {s:?}");

    if s != "." && s != ".." {
        assert_eq!(percent_decode(&seg), s.as_bytes());
    }
});
