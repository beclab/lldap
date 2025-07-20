use crate::domain::types::UserTOTPSecret;
use crate::domain::{error::Result, types::UserId};
use crate::infra::auth_service::LoginRecord;
use async_trait::async_trait;
use chrono::NaiveDateTime;
use lldap_auth::login::TokenInfo;
use std::collections::HashSet;

#[async_trait]
pub trait TcpBackendHandler: Sync {
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>>;
    async fn create_refresh_token(
        &self,
        user: &UserId,
        mfa: i64,
        jwt_refresh_token_expiry_days: i64,
    ) -> Result<(String, chrono::Duration)>;
    async fn register_jwt(
        &self,
        user: &UserId,
        jwt_hash: u64,
        token: &str,
        expiry_date: NaiveDateTime,
        mfa: i64,
    ) -> Result<()>;
    async fn check_refresh_token(
        &self,
        refresh_token_hash: u64,
        user: &UserId,
    ) -> Result<(bool, i64)>;
    async fn blacklist_jwts(&self, user: &UserId) -> Result<HashSet<u64>>;
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> Result<()>;

    /// Request a token to reset a user's password.
    /// If the user doesn't exist, returns `Ok(None)`, otherwise `Ok(Some(token))`.
    async fn start_password_reset(&self, user: &UserId) -> Result<Option<String>>;

    /// Get the user ID associated with a password reset token.
    async fn get_user_id_for_password_reset_token(&self, token: &str) -> Result<UserId>;

    async fn delete_password_reset_token(&self, token: &str) -> Result<()>;

    async fn create_login_record(&self, record: &LoginRecord) -> Result<()>;

    async fn get_user_totp_secret(&self, user_id: &UserId) -> Result<UserTOTPSecret>;

    async fn update_user_totp_secret(&self, user_id: &UserId, base32_secret: String) -> Result<()>;

    async fn access_token_list(&self) -> Result<Vec<TokenInfo>>;

    async fn delete_refresh_token_by_user(&self, user: &UserId) -> Result<()>;

    async fn set_user_initialized(&self, user_id: &UserId) -> Result<()>;
}
