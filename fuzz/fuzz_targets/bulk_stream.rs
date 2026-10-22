#![no_main]

use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use arbitrary::Arbitrary;
use futures_util::Stream;
use ipscanner::fuzzing::bulk_stream;
use ipscanner::BulkEvent;
use ipscanner_io_fuzz::Json;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};

#[derive(Debug, Arbitrary)]
enum Line {
    Raw(Vec<u8>),
    Json(Json),
    Event {
        kind: u8,
        complete: bool,
        counts: [Option<i64>; 3],
        rest: Json,
    },
}

impl Line {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Line::Raw(b) => b.clone(),
            Line::Json(j) => j.value().to_string().into_bytes(),
            Line::Event {
                kind,
                complete,
                counts,
                rest,
            } => {
                let mut obj = match rest.value() {
                    Value::Object(m) => m,
                    _ => Map::new(),
                };
                let kinds = ["meta", "result", "error", "done"];
                obj.insert("type".into(), kinds[usize::from(*kind) % 4].into());
                if *complete {
                    obj.insert("reason".into(), "complete".into());
                }
                for (key, n) in ["processed", "failed", "total"].iter().zip(counts) {
                    if let Some(n) = n {
                        obj.insert((*key).into(), (*n).into());
                    }
                }
                Value::Object(obj).to_string().into_bytes()
            }
        }
    }
}

// Events must not depend on where the body is split into chunks.
fuzz_target!(|input: (Vec<(Line, bool)>, Vec<u16>)| {
    let (lines, cuts) = input;
    let mut body = Vec::new();
    for (line, crlf) in &lines {
        body.extend(line.bytes());
        body.extend_from_slice(if *crlf { b"\r\n" } else { b"\n" });
    }

    let mut cuts: Vec<usize> = cuts
        .iter()
        .map(|c| usize::from(*c) % (body.len() + 1))
        .collect();
    cuts.sort_unstable();
    let mut chunks = Vec::new();
    let mut start = 0;
    for cut in cuts.into_iter().chain([body.len()]) {
        chunks.push(body[start..cut].to_vec());
        start = cut;
    }

    let want: Vec<Option<BulkEvent>> = body
        .split(|&b| b == b'\n')
        .map(<[u8]>::trim_ascii)
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).ok())
        .collect();

    let mut stream = bulk_stream(chunks);
    let mut cx = Context::from_waker(Waker::noop());
    let mut got = Vec::new();
    loop {
        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(item)) => got.push(item.ok()),
            Poll::Ready(None) => break,
            Poll::Pending => panic!("in-memory stream returned Pending"),
        }
    }
    assert_eq!(got, want);
    for event in got.iter().flatten() {
        event.complete();
    }
});
