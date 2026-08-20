use crate::domain::types::UserTOTPSecret;
use crate::domain::{error::Result, types::UserId};
use crate::infra::auth_service::LoginRecord;
use async_trait::async_trait;
use chrono::NaiveDateTime;
use lldap_auth::login::TokenInfo;
use std::collections::HashSet;

/// `jwt_refresh_storage.kind` for an interactive login. These are the rows
/// logout revokes as a group.
pub const REFRESH_TOKEN_KIND_SESSION: &str = "session";
/// `jwt_refresh_storage.kind` for a long-lived credential derived on behalf of
/// an app through `/auth/token/derive`. Revoked individually when the app is
/// uninstalled, never as part of a user's session cleanup.
pub const REFRESH_TOKEN_KIND_APP_CLI: &str = "app-cli";

#[async_trait]
pub trait TcpBackendHandler: Sync {
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>>;
    async fn create_refresh_token(
        &self,
        user: &UserId,
        mfa: i64,
        jwt_refresh_token_expiry_days: i64,
    ) -> Result<(String, chrono::Duration, u64)>;
    /// Mint a refresh token with an explicit lifetime, bypassing the
    /// `REFRESH_TOKEN_TTL` environment override that `create_refresh_token`
    /// applies. Long-lived credentials derived for apps must land in the
    /// database with the duration the caller asked for: a deployment that sets
    /// `REFRESH_TOKEN_TTL=30s` to keep browser sessions short would otherwise
    /// silently clamp a ten-year app grant down to half a minute.
    ///
    /// `kind` and `label` record provenance so the grant can be listed and
    /// revoked on its own; see `jwt_refresh_storage::Model`.
    async fn create_refresh_token_with(
        &self,
        user: &UserId,
        mfa: i64,
        duration: chrono::Duration,
        kind: &str,
        label: Option<&str>,
    ) -> Result<(String, chrono::Duration, u64)>;
    async fn register_jwt(
        &self,
        user: &UserId,
        jwt_hash: u64,
        token: &str,
        expiry_date: NaiveDateTime,
        mfa: i64,
        refresh_token_hash: u64,
    ) -> Result<()>;
    /// Return the `refresh_token_hash` this access token (identified by `jwt_hash`)
    /// is bound to, or `None` if the token is not present in `jwt_storage`. The
    /// value is 0 for tokens with no refresh-token binding.
    async fn get_jwt_refresh_token_hash(&self, jwt_hash: u64) -> Result<Option<u64>>;
    async fn check_refresh_token(
        &self,
        refresh_token_hash: u64,
        user: &UserId,
    ) -> Result<(bool, i64)>;
    async fn blacklist_jwts(&self, user: &UserId) -> Result<HashSet<u64>>;
    /// Like `blacklist_jwts`, but leaves access tokens that were issued from a
    /// refresh token of `spared_kind` alone. Browser logout uses this with
    /// `REFRESH_TOKEN_KIND_APP_CLI` so signing out of the desktop does not
    /// 401 an in-pod olares-cli that still holds a valid grant.
    async fn blacklist_jwts_except_kind(
        &self,
        user: &UserId,
        spared_kind: &str,
    ) -> Result<HashSet<u64>>;
    /// Blacklist only the access tokens that were issued from one refresh
    /// token, leaving the user's other sessions alone. Revoking an app grant
    /// must not sign the user out of their browser, their other apps, or
    /// TermiPass, which is what `blacklist_jwts` (filtered by user) would do.
    async fn blacklist_jwts_by_refresh_token(
        &self,
        refresh_token_hash: u64,
    ) -> Result<HashSet<u64>>;
    /// Delete the refresh-token row identified by `refresh_token_hash`. Returns
    /// the number of rows deleted (0 means no such refresh token existed).
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> Result<u64>;
    /// Delete a refresh token unless it was minted as `spared_kind`. Logout
    /// must not drop an `app-cli` grant if the request somehow presented that
    /// token; password reset and admin revoke keep using `delete_refresh_token`
    /// / `delete_refresh_token_by_user`.
    async fn delete_refresh_token_unless_kind(
        &self,
        refresh_token_hash: u64,
        spared_kind: &str,
    ) -> Result<u64>;
    /// Set the `mfa` flag on the refresh-token row identified by
    /// `refresh_token_hash`. Returns the number of rows updated.
    async fn set_refresh_token_mfa(&self, refresh_token_hash: u64, mfa: i64) -> Result<u64>;

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
