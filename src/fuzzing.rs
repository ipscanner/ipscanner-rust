//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing`.

use futures_util::stream;
use reqwest::header::HeaderMap;
use reqwest::StatusCode;

use crate::{BulkStream, Error};

pub fn error_from_response(status: StatusCode, headers: &HeaderMap, body: String) -> Error {
    crate::error::from_response(status, headers, body)
}

pub fn segment(s: &str) -> String {
    crate::client::segment(s)
}

pub fn bulk_stream(chunks: Vec<Vec<u8>>) -> BulkStream {
    BulkStream::new(stream::iter(chunks.into_iter().map(Ok::<_, Error>)))
}
