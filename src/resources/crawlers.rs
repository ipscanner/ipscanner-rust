use crate::types::CrawlerList;
use crate::{Client, Error};

/// The crawler catalogue. Keyless. Get one with [`Client::crawlers`].
#[derive(Debug, Clone, Copy)]
pub struct Crawlers<'a> {
    client: &'a Client,
}

impl<'a> Crawlers<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Crawlers { client }
    }

    /// Crawlers whose traffic can be verified from operator-published evidence.
    pub async fn list(&self) -> Result<CrawlerList, Error> {
        self.client.get("/crawlers", &[]).await
    }
}
