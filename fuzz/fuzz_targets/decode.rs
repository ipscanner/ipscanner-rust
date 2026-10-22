#![no_main]

use std::fmt::Debug;

use ipscanner::*;
use ipscanner_io_fuzz::Json;
use libfuzzer_sys::fuzz_target;
use serde::de::DeserializeOwned;
use serde::Serialize;

// Anything that decodes must encode and decode back to the same value.
fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + Debug>(data: &[u8]) -> Option<T> {
    let value: T = serde_json::from_slice(data).ok()?;
    let json = serde_json::to_vec(&value).expect("encode");
    let again: T = serde_json::from_slice(&json).expect("decode encoded value");
    assert_eq!(value, again);
    Some(value)
}

fn decode(kind: u8, data: &[u8]) {
    match kind % 30 {
        0 => drop(roundtrip::<LookupResult>(data)),
        1 => drop(roundtrip::<VpnResponse>(data)),
        2 => drop(roundtrip::<ProxyResponse>(data)),
        3 => drop(roundtrip::<GeolocationResponse>(data)),
        4 => drop(roundtrip::<AsnResponse>(data)),
        5 => drop(roundtrip::<WhoisResponse>(data)),
        6 => drop(roundtrip::<History>(data)),
        7 => drop(roundtrip::<MyIp>(data)),
        8 => drop(roundtrip::<BulkCheck>(data)),
        9 => {
            if let Some(event) = roundtrip::<BulkEvent>(data) {
                event.complete();
            }
        }
        10 => drop(roundtrip::<AgentCheck>(data)),
        11 => drop(roundtrip::<AgentBatch>(data)),
        12 => drop(roundtrip::<CrawlerVerification>(data)),
        13 => drop(roundtrip::<Vec<AllowlistAgent>>(data)),
        14 => drop(roundtrip::<AgentSelfCheck>(data)),
        15 => drop(roundtrip::<EdgeCheck>(data)),
        16 => drop(roundtrip::<SitePolicy>(data)),
        17 => drop(roundtrip::<GateVerification>(data)),
        18 => drop(roundtrip::<EmailCheck>(data)),
        19 => drop(roundtrip::<ProvenanceCheck>(data)),
        20 => drop(roundtrip::<ChainVerification>(data)),
        21 => drop(roundtrip::<AnchoredVerification>(data)),
        22 => drop(roundtrip::<Chain>(data)),
        23 => drop(roundtrip::<Vec<Jurisdiction>>(data)),
        24 => drop(roundtrip::<Limits>(data)),
        25 => drop(roundtrip::<UsageSummary>(data)),
        26 => drop(roundtrip::<AsnTop>(data)),
        27 => drop(roundtrip::<AsnSearch>(data)),
        28 => drop(roundtrip::<AsnDetail>(data)),
        _ => drop(roundtrip::<CrawlerList>(data)),
    }
}

fuzz_target!(|input: (u8, bool, Json, &[u8])| {
    let (kind, raw, json, bytes) = input;
    if raw {
        decode(kind, bytes);
    } else {
        decode(kind, json.value().to_string().as_bytes());
    }
});
