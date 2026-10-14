use serde::{Deserialize, Serialize};

/// Response of `POST /v1/email/check`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailCheck {
    pub email: String,
    /// `valid`, `invalid`, `risky` or `unknown`.
    pub status: String,
    /// `syntax`, `no_mx`, `null_mx`, `disposable`, `typo`, `role`, `dns_error` or `quota`. Null when valid.
    pub reason: Option<String>,
    /// The address with a webmail typo fixed, when there is one.
    pub suggestion: Option<String>,
    pub domain: String,
    pub checks: EmailChecks,
    /// Always `not_checked`: the mailbox itself is not probed.
    pub mailbox: String,
}

/// The checks behind an email status.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EmailChecks {
    pub syntax: bool,
    /// Null when DNS was not asked or did not answer.
    pub mx: Option<bool>,
    pub disposable: bool,
    pub role: bool,
    pub free_provider: bool,
}
