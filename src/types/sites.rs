use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Response of `GET /v1/sites/{id}/policy`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SitePolicy {
    pub site: String,
    /// `monitor` or `enforce`.
    pub mode: String,
    /// Traffic class to `allow`, `flag` or `block`.
    pub policy: HashMap<String, String>,
    pub version: i64,
    pub updated_at: String,
}
