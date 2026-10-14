use serde_json::json;

use crate::types::EmailCheck;
use crate::{Client, Error};

/// Email address checks. Get one with [`Client::email`].
#[derive(Debug, Clone, Copy)]
pub struct Email<'a> {
    client: &'a Client,
}

impl<'a> Email<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Email { client }
    }

    /// Checks one address: syntax, throwaway domains, mail servers, typos and role addresses. One request.
    pub async fn check(&self, email: &str) -> Result<EmailCheck, Error> {
        self.client
            .post("/email/check", &json!({ "email": email }))
            .await
    }
}
