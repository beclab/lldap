#[derive(Debug, PartialEq, Eq)]
pub enum StatusReason {
    Unknown,
    Unauthorized,
    Forbidden,
    NotFound,
    AlreadyExists,
    BadRequest,
    InternalError,
    ServiceUnavailable,
}

impl StatusReason {
    pub fn as_str(&self) -> &str {
        match self {
            StatusReason::Unknown => "",
            StatusReason::Unauthorized => "Unauthorized",
            StatusReason::Forbidden => "Forbidden",
            StatusReason::NotFound => "NotFound",
            StatusReason::AlreadyExists => "AlreadyExists",
            StatusReason::BadRequest => "BadRequest",
            StatusReason::InternalError => "InternalError",
            StatusReason::ServiceUnavailable => "ServiceUnavailable",
        }
    }
}
