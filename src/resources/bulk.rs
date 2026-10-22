use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::{self, Stream, StreamExt};

use crate::types::{BulkCheck, BulkEvent, BulkRequest};
use crate::{Client, Error};

const STREAM_TIMEOUT: Duration = Duration::from_secs(300);

/// Bulk checks. Get one with [`Client::bulk`].
#[derive(Debug, Clone, Copy)]
pub struct Bulk<'a> {
    client: &'a Client,
}

impl<'a> Bulk<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Bulk { client }
    }

    /// Checks a list of IPs and returns every result in one response.
    pub async fn check(&self, req: &BulkRequest) -> Result<BulkCheck, Error> {
        self.client.post("/bulk/check", req).await
    }

    /// Streams one event per IP as NDJSON; 400 and 429 before the stream starts are returned here.
    pub async fn stream(&self, req: &BulkRequest) -> Result<BulkStream, Error> {
        let res = self
            .client
            .post_raw("/ip/bulk", req, Some(STREAM_TIMEOUT))
            .await?;
        Ok(BulkStream::new(res.bytes_stream()))
    }
}

/// A stream of [`BulkEvent`]s parsed from NDJSON.
pub struct BulkStream {
    inner: Pin<Box<dyn Stream<Item = Result<BulkEvent, Error>> + Send>>,
}

impl fmt::Debug for BulkStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BulkStream").finish_non_exhaustive()
    }
}

impl BulkStream {
    pub(crate) fn new<S, B, E>(body: S) -> Self
    where
        S: Stream<Item = Result<B, E>> + Send + 'static,
        B: AsRef<[u8]> + 'static,
        E: Into<Error> + 'static,
    {
        BulkStream {
            inner: Box::pin(ndjson(body)),
        }
    }
}

impl Stream for BulkStream {
    type Item = Result<BulkEvent, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

struct LineState<S> {
    body: Pin<Box<S>>,
    buf: Vec<u8>,
    ready: VecDeque<Result<BulkEvent, Error>>,
    done: bool,
}

impl<S> LineState<S> {
    fn drain_lines(&mut self) {
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            self.push_line(&line);
        }
        if self.done && !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            self.push_line(&line);
        }
    }

    fn push_line(&mut self, line: &[u8]) {
        let line = line.trim_ascii();
        if !line.is_empty() {
            self.ready
                .push_back(serde_json::from_slice(line).map_err(Error::from));
        }
    }
}

fn ndjson<S, B, E>(body: S) -> impl Stream<Item = Result<BulkEvent, Error>> + Send
where
    S: Stream<Item = Result<B, E>> + Send + 'static,
    B: AsRef<[u8]> + 'static,
    E: Into<Error> + 'static,
{
    let state = LineState {
        body: Box::pin(body),
        buf: Vec::new(),
        ready: VecDeque::new(),
        done: false,
    };
    stream::unfold(state, |mut st| async move {
        loop {
            if let Some(item) = st.ready.pop_front() {
                return Some((item, st));
            }
            if st.done {
                return None;
            }
            match st.body.next().await {
                Some(Ok(chunk)) => {
                    st.buf.extend_from_slice(chunk.as_ref());
                    st.drain_lines();
                }
                Some(Err(e)) => {
                    st.done = true;
                    st.buf.clear();
                    return Some((Err(e.into()), st));
                }
                None => {
                    st.done = true;
                    st.drain_lines();
                }
            }
        }
    })
}
