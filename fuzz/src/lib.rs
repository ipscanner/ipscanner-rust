use arbitrary::Arbitrary;
use serde_json::{Map, Value};

const KEYS: &[&str] = &[
    "error",
    "message",
    "details",
    "reason",
    "retryAfter",
    "resetAt",
    "resetDate",
    "limit",
    "usage",
    "remaining",
    "needed",
    "plan",
    "upgrade",
    "url",
    "type",
    "index",
    "total",
    "input",
    "ip",
    "processed",
    "failed",
    "score",
    "grade",
    "verdict",
    "locked",
    "planRequired",
];

/// A JSON value biased towards the field names the API uses.
#[derive(Debug, Arbitrary)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(Key, Json)>),
}

#[derive(Debug, Arbitrary)]
pub struct Key(u8, String);

impl Key {
    fn name(&self) -> String {
        match KEYS.get(usize::from(self.0)) {
            Some(k) => (*k).to_string(),
            None => self.1.clone(),
        }
    }
}

impl Json {
    pub fn value(&self) -> Value {
        match self {
            Json::Null => Value::Null,
            Json::Bool(b) => Value::Bool(*b),
            Json::Int(n) => Value::from(*n),
            Json::Uint(n) => Value::from(*n),
            Json::Float(f) => Value::from(*f),
            Json::Str(s) => Value::String(s.clone()),
            Json::Array(items) => Value::Array(items.iter().map(Json::value).collect()),
            Json::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(k, v)| (k.name(), v.value()))
                    .collect::<Map<_, _>>(),
            ),
        }
    }
}

/// A response body: raw text, or JSON built from [`Json`].
#[derive(Debug, Arbitrary)]
pub enum Body {
    Raw(String),
    Json(Json),
}

impl Body {
    pub fn text(&self) -> String {
        match self {
            Body::Raw(s) => s.clone(),
            Body::Json(j) => j.value().to_string(),
        }
    }
}
