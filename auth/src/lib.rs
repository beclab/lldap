#![forbid(non_ascii_idents)]
#![allow(clippy::nonstandard_macro_braces)]
// use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

pub mod opaque;

/// The messages for the 3-step OPAQUE and simple login process.
pub mod login {
    use super::{types::UserId, *};

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerData {
        pub username: UserId,
        pub server_login: opaque::server::login::ServerLogin,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientLoginStartRequest {
        pub username: UserId,
        pub login_start_request: opaque::server::login::CredentialRequest,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct TotpVerifyRequest {
        pub token: String,
    }
    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerLoginStartResponse {
        /// Base64, encrypted ServerData to be passed back to the server.
        pub server_data: String,
        pub credential_response: opaque::client::login::CredentialResponse,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientLoginFinishRequest {
        /// Encrypted ServerData from the previous step.
        pub server_data: String,
        pub credential_finalization: opaque::client::login::CredentialFinalization,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientSimpleLoginRequest {
        pub username: UserId,
        pub password: String,
    }

    impl fmt::Debug for ClientSimpleLoginRequest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ClientSimpleLoginRequest")
                .field("username", &self.username.as_str())
                .field("password", &"***********")
                .finish()
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerLoginResponse {
        pub token: String,
        #[serde(rename = "refreshToken", skip_serializing_if = "Option::is_none")]
        pub refresh_token: Option<String>,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct TokenInfo {
        pub access_token: String,
        pub is_blacklisted: bool,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct TokenVerifyRequest {
        pub access_token: String,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct TokenInvalidateRequest {
        pub access_token: String,
    }
}

/// The messages for the 3-step OPAQUE registration process.
/// It is used to reset a user's password.
pub mod registration {
    use super::{types::UserId, *};

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerData {
        pub username: UserId,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientRegistrationStartRequest {
        pub username: UserId,
        pub registration_start_request: opaque::server::registration::RegistrationRequest,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerRegistrationStartResponse {
        /// Base64, encrypted ServerData to be passed back to the server.
        pub server_data: String,
        pub registration_response: opaque::client::registration::RegistrationResponse,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientRegistrationFinishRequest {
        /// Encrypted ServerData from the previous step.
        pub server_data: String,
        pub registration_upload: opaque::server::registration::RegistrationUpload,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientSimpleRegisterRequest {
        pub username: UserId,
        // pub email: String,
        // pub display: Option<String>,
        pub password: String,
    }

    impl fmt::Debug for crate::registration::ClientSimpleRegisterRequest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ClientSimpleRegisterRequest")
                .field("username", &self.username.as_str())
                //.field("email", &self.email.as_str())
                //.field("display", &self.display.as_str())
                .field("password", &"***********")
                .finish()
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerRegisterResponse {
        pub token: String,
        #[serde(rename = "refreshToken", skip_serializing_if = "Option::is_none")]
        pub refresh_token: Option<String>,
    }
}

/// The messages for the 3-step OPAQUE registration process.
/// It is used to reset a user's password.
pub mod password_reset {
    use super::*;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerPasswordResetResponse {
        #[serde(rename = "userId")]
        pub user_id: String,
        pub token: String,
    }
}

pub mod totp_bind {
    use super::*;
    #[derive(Serialize, Deserialize, Clone)]
    pub struct TotpBindResponse {
        pub base32_secret: String,
    }
}

pub mod types {
    use serde::{Deserialize, Serialize};

    #[cfg(feature = "sea_orm")]
    use sea_orm::{DbErr, DeriveValueType, TryFromU64, Value};

    #[derive(
        PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Default, Hash, Serialize, Deserialize,
    )]
    #[cfg_attr(feature = "sea_orm", derive(DeriveValueType))]
    #[serde(from = "String")]
    pub struct CaseInsensitiveString(String);

    impl CaseInsensitiveString {
        pub fn new(s: &str) -> Self {
            Self(s.to_ascii_lowercase())
        }

        pub fn as_str(&self) -> &str {
            self.0.as_str()
        }

        pub fn into_string(self) -> String {
            self.0
        }
    }

    impl From<String> for CaseInsensitiveString {
        fn from(mut s: String) -> Self {
            s.make_ascii_lowercase();
            Self(s)
        }
    }

    impl From<&String> for CaseInsensitiveString {
        fn from(s: &String) -> Self {
            Self::new(s.as_str())
        }
    }

    impl From<&str> for CaseInsensitiveString {
        fn from(s: &str) -> Self {
            Self::new(s)
        }
    }

    #[derive(
        PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Default, Hash, Serialize, Deserialize,
    )]
    #[cfg_attr(feature = "sea_orm", derive(DeriveValueType))]
    #[serde(from = "CaseInsensitiveString")]
    pub struct UserId(CaseInsensitiveString);

    impl UserId {
        pub fn new(s: &str) -> Self {
            s.into()
        }
        pub fn as_str(&self) -> &str {
            self.0.as_str()
        }
        pub fn into_string(self) -> String {
            self.0.into_string()
        }
    }
    impl<T> From<T> for UserId
    where
        T: Into<CaseInsensitiveString>,
    {
        fn from(s: T) -> Self {
            Self(s.into())
        }
    }
    impl std::fmt::Display for UserId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{}", self.0.as_str())
        }
    }

    #[cfg(feature = "sea_orm")]
    impl From<&UserId> for Value {
        fn from(user_id: &UserId) -> Self {
            user_id.as_str().into()
        }
    }
    #[cfg(feature = "sea_orm")]
    impl TryFromU64 for UserId {
        fn try_from_u64(_n: u64) -> Result<Self, DbErr> {
            Err(DbErr::ConvertFromU64(
                "UserId cannot be constructed from u64",
            ))
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    pub exp: i64,
    pub iat: i64,
    pub username: String,
    pub groups: HashSet<String>,
    pub mfa: i64,
    pub jid: u64,
}
