use crate::types::{Limits, UsageSummary};
use crate::{Client, Error};

/// Account limits and usage. Get one with [`Client::account`].
#[derive(Debug, Clone, Copy)]
pub struct Account<'a> {
    client: &'a Client,
}

impl<'a> Account<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Account { client }
    }

    /// Your plan's monthly, daily and hourly limits.
    pub async fn limits(&self) -> Result<Limits, Error> {
        self.client.get("/user/limits", &[]).await
    }

    /// Usage this billing period.
    pub async fn usage(&self) -> Result<UsageSummary, Error> {
        self.client.get("/usage/summary", &[]).await
    }
}
