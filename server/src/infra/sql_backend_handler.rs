use super::tcp_backend_handler::{TcpBackendHandler, REFRESH_TOKEN_KIND_SESSION};
use crate::domain::types::UserTOTPSecret;
use crate::domain::{
    error::*,
    model::{self, JwtRefreshStorageColumn, JwtStorageColumn, PasswordResetTokensColumn},
    sql_backend_handler::SqlBackendHandler,
    types::UserId,
};
use crate::infra::auth_service::LoginRecord;
use async_trait::async_trait;
use chrono::NaiveDateTime;
use lldap_auth::login::TokenInfo;
use sea_orm::{
    sea_query::{Cond, Expr},
    ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, IntoActiveModel, NotSet, QueryFilter,
    QuerySelect, Set, TransactionTrait,
};
use std::collections::HashSet;
use tracing::{debug, instrument};

fn gen_random_string(len: usize) -> String {
    use rand::{distributions::Alphanumeric, rngs::SmallRng, Rng, SeedableRng};
    let mut rng = SmallRng::from_entropy();
    std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(len)
        .collect()
}

#[async_trait]
impl TcpBackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug")]
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>> {
        Ok(model::JwtStorage::find()
            .select_only()
            .column(JwtStorageColumn::JwtHash)
            .filter(JwtStorageColumn::Blacklisted.eq(true))
            .into_tuple::<(i64,)>()
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(|m| m.0 as u64)
            .collect::<HashSet<u64>>())
    }

    #[instrument(skip_all, level = "debug")]
    async fn create_refresh_token(
        &self,
        user: &UserId,
        mfa: i64,
        jwt_refresh_token_expiry_days: i64,
    ) -> Result<(String, chrono::Duration, u64)> {
        // Use REFRESH_TOKEN_TTL if set (e.g. `30s`, `5m`, `1h`, `7d`), otherwise fall back
        // to the configured days.
        let duration = crate::infra::auth_service::ttl_from_env(
            "REFRESH_TOKEN_TTL",
            jwt_refresh_token_expiry_days,
        );
        self.create_refresh_token_with(user, mfa, duration, REFRESH_TOKEN_KIND_SESSION, None)
            .await
    }

    #[instrument(skip_all, level = "debug")]
    async fn create_refresh_token_with(
        &self,
        user: &UserId,
        mfa: i64,
        duration: chrono::Duration,
        kind: &str,
        label: Option<&str>,
    ) -> Result<(String, chrono::Duration, u64)> {
        debug!(?user, ?kind);
        // TODO: Initialize the rng only once. Maybe Arc<Cell>?
        let refresh_token = gen_random_string(100);
        let refresh_token_hash = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut s = DefaultHasher::new();
            refresh_token.hash(&mut s);
            s.finish()
        };
        let new_token = model::jwt_refresh_storage::Model {
            refresh_token_hash: refresh_token_hash as i64,
            user_id: user.clone(),
            expiry_date: chrono::Utc::now().naive_utc() + duration,
            mfa: mfa,
            kind: kind.to_owned(),
            label: label.map(str::to_owned),
        }
        .into_active_model();
        new_token.insert(&self.sql_pool).await?;
        Ok((refresh_token, duration, refresh_token_hash))
    }

    #[instrument(skip_all, level = "debug")]
    async fn register_jwt(
        &self,
        user: &UserId,
        jwt_hash: u64,
        token: &str,
        expiry_date: NaiveDateTime,
        mfa: i64,
        refresh_token_hash: u64,
    ) -> Result<()> {
        debug!(?user, ?jwt_hash);
        let new_token = model::jwt_storage::Model {
            jwt_hash: jwt_hash as i64,
            token: token.to_string(),
            user_id: user.clone(),
            blacklisted: false,
            expiry_date,
            mfa,
            refresh_token_hash: refresh_token_hash as i64,
        }
        .into_active_model();
        let existing_hash = model::jwt_storage::Entity::find()
            .filter(model::jwt_storage::Column::JwtHash.eq(jwt_hash as i64))
            .one(&self.sql_pool)
            .await?;
        if existing_hash.is_some() {
            return Ok(());
        }
        new_token.insert(&self.sql_pool).await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug")]
    async fn get_jwt_refresh_token_hash(&self, jwt_hash: u64) -> Result<Option<u64>> {
        Ok(model::jwt_storage::Entity::find_by_id(jwt_hash as i64)
            .one(&self.sql_pool)
            .await?
            .map(|m| m.refresh_token_hash as u64))
    }

    #[instrument(skip_all, level = "debug")]
    async fn check_refresh_token(
        &self,
        refresh_token_hash: u64,
        user: &UserId,
    ) -> Result<(bool, i64)> {
        debug!(?user);

        let record = model::JwtRefreshStorage::find_by_id(refresh_token_hash as i64)
            .filter(JwtRefreshStorageColumn::UserId.eq(user))
            .filter(JwtRefreshStorageColumn::ExpiryDate.gt(chrono::Utc::now().naive_utc()))
            .one(&self.sql_pool)
            .await?;
        match record {
            Some(record) => Ok((true, record.mfa)),
            None => Ok((false, 0)),
        }
    }

    #[instrument(skip_all, level = "debug")]
    async fn blacklist_jwts(&self, user: &UserId) -> Result<HashSet<u64>> {
        debug!(?user);
        let valid_tokens = model::JwtStorage::find()
            .select_only()
            .column(JwtStorageColumn::JwtHash)
            .filter(
                Cond::all()
                    .add(JwtStorageColumn::UserId.eq(user))
                    .add(JwtStorageColumn::Blacklisted.eq(false)),
            )
            .into_tuple::<(i64,)>()
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(|t| t.0 as u64)
            .collect::<HashSet<u64>>();
        model::JwtStorage::update_many()
            .col_expr(JwtStorageColumn::Blacklisted, Expr::value(true))
            .filter(JwtStorageColumn::UserId.eq(user))
            .exec(&self.sql_pool)
            .await?;
        Ok(valid_tokens)
    }

    #[instrument(skip_all, level = "debug")]
    async fn blacklist_jwts_except_kind(
        &self,
        user: &UserId,
        spared_kind: &str,
    ) -> Result<HashSet<u64>> {
        debug!(?user, ?spared_kind);
        let spared_hashes: Vec<i64> = model::JwtRefreshStorage::find()
            .select_only()
            .column(JwtRefreshStorageColumn::RefreshTokenHash)
            .filter(JwtRefreshStorageColumn::UserId.eq(user))
            .filter(JwtRefreshStorageColumn::Kind.eq(spared_kind))
            .into_tuple::<i64>()
            .all(&self.sql_pool)
            .await?;
        if spared_hashes.is_empty() {
            return self.blacklist_jwts(user).await;
        }

        let filter = Cond::all()
            .add(JwtStorageColumn::UserId.eq(user))
            .add(JwtStorageColumn::Blacklisted.eq(false))
            .add(JwtStorageColumn::RefreshTokenHash.is_not_in(spared_hashes.clone()));
        let valid_tokens = model::JwtStorage::find()
            .select_only()
            .column(JwtStorageColumn::JwtHash)
            .filter(filter.clone())
            .into_tuple::<(i64,)>()
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(|t| t.0 as u64)
            .collect::<HashSet<u64>>();
        model::JwtStorage::update_many()
            .col_expr(JwtStorageColumn::Blacklisted, Expr::value(true))
            .filter(
                Cond::all()
                    .add(JwtStorageColumn::UserId.eq(user))
                    .add(JwtStorageColumn::RefreshTokenHash.is_not_in(spared_hashes)),
            )
            .exec(&self.sql_pool)
            .await?;
        Ok(valid_tokens)
    }

    #[instrument(skip_all, level = "debug")]
    async fn blacklist_jwts_by_refresh_token(
        &self,
        refresh_token_hash: u64,
    ) -> Result<HashSet<u64>> {
        debug!(?refresh_token_hash);
        let valid_tokens = model::JwtStorage::find()
            .select_only()
            .column(JwtStorageColumn::JwtHash)
            .filter(
                Cond::all()
                    .add(JwtStorageColumn::RefreshTokenHash.eq(refresh_token_hash as i64))
                    .add(JwtStorageColumn::Blacklisted.eq(false)),
            )
            .into_tuple::<(i64,)>()
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(|t| t.0 as u64)
            .collect::<HashSet<u64>>();
        model::JwtStorage::update_many()
            .col_expr(JwtStorageColumn::Blacklisted, Expr::value(true))
            .filter(JwtStorageColumn::RefreshTokenHash.eq(refresh_token_hash as i64))
            .exec(&self.sql_pool)
            .await?;
        Ok(valid_tokens)
    }

    #[instrument(skip_all, level = "debug")]
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> Result<u64> {
        let result = model::JwtRefreshStorage::delete_by_id(refresh_token_hash as i64)
            .exec(&self.sql_pool)
            .await?;
        Ok(result.rows_affected)
    }

    #[instrument(skip_all, level = "debug")]
    async fn delete_refresh_token_unless_kind(
        &self,
        refresh_token_hash: u64,
        spared_kind: &str,
    ) -> Result<u64> {
        if let Some(row) = model::JwtRefreshStorage::find_by_id(refresh_token_hash as i64)
            .one(&self.sql_pool)
            .await?
        {
            if row.kind == spared_kind {
                return Ok(0);
            }
        }
        self.delete_refresh_token(refresh_token_hash).await
    }

    #[instrument(skip_all, level = "debug")]
    async fn set_refresh_token_mfa(&self, refresh_token_hash: u64, mfa: i64) -> Result<u64> {
        let result = model::JwtRefreshStorage::update_many()
            .col_expr(JwtRefreshStorageColumn::Mfa, Expr::value(mfa))
            .filter(JwtRefreshStorageColumn::RefreshTokenHash.eq(refresh_token_hash as i64))
            .exec(&self.sql_pool)
            .await?;
        Ok(result.rows_affected)
    }

    #[instrument(skip_all, level = "debug")]
    async fn start_password_reset(&self, user: &UserId) -> Result<Option<String>> {
        debug!(?user);
        if model::User::find_by_id(user.clone())
            .one(&self.sql_pool)
            .await?
            .is_none()
        {
            debug!("User not found");
            return Ok(None);
        }

        let token = gen_random_string(100);
        let duration = chrono::Duration::minutes(10);

        let new_token = model::password_reset_tokens::Model {
            token: token.clone(),
            user_id: user.clone(),
            expiry_date: chrono::Utc::now().naive_utc() + duration,
        }
        .into_active_model();
        new_token.insert(&self.sql_pool).await?;
        Ok(Some(token))
    }

    #[instrument(skip_all, level = "debug", ret)]
    async fn get_user_id_for_password_reset_token(&self, token: &str) -> Result<UserId> {
        Ok(model::PasswordResetTokens::find_by_id(token.to_owned())
            .filter(PasswordResetTokensColumn::ExpiryDate.gt(chrono::Utc::now().naive_utc()))
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| DomainError::EntityNotFound("Invalid reset token".to_owned()))?
            .user_id)
    }

    #[instrument(skip_all, level = "debug")]
    async fn delete_password_reset_token(&self, token: &str) -> Result<()> {
        let result = model::PasswordResetTokens::delete_by_id(token.to_owned())
            .exec(&self.sql_pool)
            .await?;
        if result.rows_affected == 0 {
            return Err(DomainError::EntityNotFound(format!(
                "No such password reset token: '{}'",
                token
            )));
        }
        Ok(())
    }

    #[instrument(skip_all, level = "debug")]
    async fn create_login_record(&self, record: &LoginRecord) -> Result<()> {
        debug!(?record);
        let now = chrono::Utc::now().naive_utc();
        let login_record = model::login_record::ActiveModel {
            user_id: Set(record.user_id.clone()),
            success: Set(record.success),
            reason: Set(record.reason.to_string()),
            source_ip: Set(record.source_ip.to_string()),
            user_agent: Set(record.user_agent.to_string()),
            creation_date: Set(now),
            id: NotSet,
        }
        .into_active_model();
        login_record.insert(&self.sql_pool).await?;
        Ok(())
    }
    #[instrument(skip_all, level = "debug")]
    async fn get_user_totp_secret(&self, user_id: &UserId) -> Result<UserTOTPSecret> {
        let user = model::User::find_by_id(user_id.to_owned())
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| {
                DomainError::EntityNotFound(format!("No such user {:?}", user_id.to_string()))
            })?;

        Ok(UserTOTPSecret {
            totp_secret: user.totp_secret.to_owned(),
        })
    }
    #[instrument(skip_all, level = "debug")]
    async fn update_user_totp_secret(&self, user_id: &UserId, base32_secret: String) -> Result<()> {
        let exist_user = model::User::find_by_id(user_id.clone())
            .one(&self.sql_pool)
            .await?;
        if exist_user.is_none() {
            return Err(DomainError::EntityNotFound(format!(
                "No such user {:?}",
                user_id.as_str()
            )));
        }
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(user_id.clone()),
            totp_secret: ActiveValue::Set(Some(base32_secret)),
            ..Default::default()
        };
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(async move {
                    user_update
                        .update(transaction)
                        .await
                        .map(|_| ())
                        .map_err(|e| DomainError::from(e))
                })
            })
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug")]
    async fn access_token_list(&self) -> Result<Vec<TokenInfo>> {
        let tokens = model::JwtStorage::find()
            .select_only()
            .columns([JwtStorageColumn::Token, JwtStorageColumn::Blacklisted])
            .filter(JwtStorageColumn::Token.is_not_null())
            .into_tuple::<(String, bool)>()
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(|(token, is_blacklisted)| TokenInfo {
                access_token: token,
                is_blacklisted,
            })
            .collect::<Vec<TokenInfo>>();
        Ok(tokens)
    }
    #[instrument(skip_all, level = "debug")]
    async fn delete_refresh_token_by_user(&self, user: &UserId) -> Result<()> {
        model::JwtRefreshStorage::delete_many()
            .filter(JwtRefreshStorageColumn::UserId.eq(user.clone()))
            .exec(&self.sql_pool)
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug")]
    async fn set_user_initialized(&self, user_id: &UserId) -> Result<()> {
        let exist_user = model::User::find_by_id(user_id.clone())
            .one(&self.sql_pool)
            .await?;
        if exist_user.is_none() {
            return Err(DomainError::EntityNotFound(format!(
                "No such user {:?}",
                user_id.as_str()
            )));
        }
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(user_id.clone()),
            initialized: Set(true),
            ..Default::default()
        };
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(async move {
                    user_update
                        .update(transaction)
                        .await
                        .map(|_| ())
                        .map_err(|e| DomainError::from(e))
                })
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        sql_backend_handler::tests::{get_default_config, get_in_memory_db},
        sql_migrations::migrate_from_version,
        sql_tables::{init_table, SchemaVersion, LAST_SCHEMA_VERSION},
    };
    use crate::infra::jwt_sql_tables;
    use crate::infra::tcp_backend_handler::REFRESH_TOKEN_KIND_APP_CLI;
    use chrono::Duration;
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use serial_test::serial;

    const TEST_USER: &str = "alice";

    /// Same bring-up order as `main`: domain tables, then the JWT tables, then
    /// the migrations that add columns to them.
    ///
    /// Only the tail of the migration chain is replayed. Replaying it from v1
    /// on SQLite trips over v12, which adds an AUTOINCREMENT column with ALTER
    /// TABLE — valid on Postgres, which is what deployments run, but not on
    /// SQLite. Starting at v12 covers exactly the migrations that touch the
    /// JWT tables (mfa, refresh_token_hash, kind/label), which is what these
    /// tests exercise.
    ///
    /// The owning user is inserted with raw SQL for the same reason: the
    /// `users` entity has the `user_index` column that the skipped migration
    /// would have added, and the refresh-token rows only need the user to
    /// exist so their foreign key resolves.
    async fn new_handler() -> SqlBackendHandler {
        let sql_pool = get_in_memory_db().await;
        init_table(&sql_pool).await.unwrap();
        jwt_sql_tables::init_table(&sql_pool).await.unwrap();
        migrate_from_version(&sql_pool, SchemaVersion(12), LAST_SCHEMA_VERSION)
            .await
            .unwrap();
        sql_pool
            .execute(Statement::from_string(
                DbBackend::Sqlite,
                format!(
                    r#"INSERT INTO users (user_id, email, display_name, creation_date, uuid)
                       VALUES ("{user}", "{user}@bob.bob", "{user}", "1970-01-01 00:00:00", "abc")"#,
                    user = TEST_USER,
                ),
            ))
            .await
            .unwrap();
        SqlBackendHandler::new(get_default_config(), sql_pool)
    }

    async fn refresh_row(
        handler: &SqlBackendHandler,
        hash: u64,
    ) -> model::jwt_refresh_storage::Model {
        model::JwtRefreshStorage::find_by_id(hash as i64)
            .one(&handler.sql_pool)
            .await
            .unwrap()
            .expect("refresh token row should exist")
    }

    /// A deployment that shortens sessions with REFRESH_TOKEN_TTL must not
    /// silently shorten derived app grants with it: `create_refresh_token_with`
    /// takes the caller's duration verbatim. The session path in the same test
    /// shows the env var is genuinely in effect, so this is a real bypass and
    /// not an unset variable.
    #[tokio::test]
    #[serial]
    async fn derived_token_ignores_refresh_token_ttl_env() {
        let handler = new_handler().await;
        let user = UserId::new(TEST_USER);
        std::env::set_var("REFRESH_TOKEN_TTL", "30s");

        let (_, duration, hash) = handler
            .create_refresh_token_with(
                &user,
                1,
                Duration::days(3650),
                REFRESH_TOKEN_KIND_APP_CLI,
                Some("app:lares:alice"),
            )
            .await
            .unwrap();
        assert_eq!(duration, Duration::days(3650));

        let (_, session_duration, _) = handler.create_refresh_token(&user, 0, 30).await.unwrap();
        assert_eq!(session_duration, Duration::seconds(30));

        std::env::remove_var("REFRESH_TOKEN_TTL");

        let row = refresh_row(&handler, hash).await;
        assert_eq!(row.kind, REFRESH_TOKEN_KIND_APP_CLI);
        assert_eq!(row.label.as_deref(), Some("app:lares:alice"));
        // The mfa level the caller asked for has to survive the round trip:
        // access tokens refreshed from the grant inherit it, and mfa=0 ones
        // are rejected at the edge for users on the two_factor policy.
        assert_eq!(handler.check_refresh_token(hash, &user).await.unwrap().1, 1);
    }

    #[tokio::test]
    #[serial]
    async fn session_tokens_are_recorded_as_such() {
        let handler = new_handler().await;
        let user = UserId::new(TEST_USER);
        let (_, _, hash) = handler.create_refresh_token(&user, 0, 30).await.unwrap();
        let row = refresh_row(&handler, hash).await;
        assert_eq!(row.kind, REFRESH_TOKEN_KIND_SESSION);
        assert_eq!(row.label, None);
    }

    /// Revoking an app grant must not sign the user out everywhere else.
    /// `blacklist_jwts` filters by user and would take the browser session
    /// down with the app; the by-refresh-token variant must touch only the
    /// access tokens minted from the grant being revoked.
    #[tokio::test]
    #[serial]
    async fn revoking_a_grant_spares_the_users_other_sessions() {
        let handler = new_handler().await;
        let user = UserId::new(TEST_USER);
        let expiry = chrono::Utc::now().naive_utc() + Duration::days(1);

        let (_, _, session_hash) = handler.create_refresh_token(&user, 0, 30).await.unwrap();
        let (_, _, grant_hash) = handler
            .create_refresh_token_with(
                &user,
                0,
                Duration::days(3650),
                REFRESH_TOKEN_KIND_APP_CLI,
                Some("app:lares:alice"),
            )
            .await
            .unwrap();

        let session_jwt = 1111u64;
        let grant_jwt = 2222u64;
        handler
            .register_jwt(&user, session_jwt, "browser", expiry, 0, session_hash)
            .await
            .unwrap();
        handler
            .register_jwt(&user, grant_jwt, "app", expiry, 0, grant_hash)
            .await
            .unwrap();

        let blacklisted = handler
            .blacklist_jwts_by_refresh_token(grant_hash)
            .await
            .unwrap();
        assert_eq!(blacklisted, HashSet::from([grant_jwt]));

        let stored = handler.get_jwt_blacklist().await.unwrap();
        assert!(stored.contains(&grant_jwt));
        assert!(
            !stored.contains(&session_jwt),
            "revoking an app grant must leave the user's browser session usable"
        );
    }

    /// Browser logout blacklists session access tokens but must leave the
    /// app-cli grant (refresh row + access tokens issued from it) intact.
    #[tokio::test]
    #[serial]
    async fn logout_spares_app_cli_tokens() {
        let handler = new_handler().await;
        let user = UserId::new(TEST_USER);
        let expiry = chrono::Utc::now().naive_utc() + Duration::days(1);

        let (_, _, session_hash) = handler.create_refresh_token(&user, 0, 30).await.unwrap();
        let (_, _, grant_hash) = handler
            .create_refresh_token_with(
                &user,
                1,
                Duration::days(3650),
                REFRESH_TOKEN_KIND_APP_CLI,
                Some("app:lares:alice"),
            )
            .await
            .unwrap();

        let session_jwt = 1111u64;
        let grant_jwt = 2222u64;
        handler
            .register_jwt(&user, session_jwt, "browser", expiry, 0, session_hash)
            .await
            .unwrap();
        handler
            .register_jwt(&user, grant_jwt, "app", expiry, 1, grant_hash)
            .await
            .unwrap();

        assert_eq!(
            handler
                .delete_refresh_token_unless_kind(session_hash, REFRESH_TOKEN_KIND_APP_CLI)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            handler
                .delete_refresh_token_unless_kind(grant_hash, REFRESH_TOKEN_KIND_APP_CLI)
                .await
                .unwrap(),
            0,
            "logout must not delete an app-cli refresh token"
        );
        refresh_row(&handler, grant_hash).await;

        let blacklisted = handler
            .blacklist_jwts_except_kind(&user, REFRESH_TOKEN_KIND_APP_CLI)
            .await
            .unwrap();
        assert_eq!(blacklisted, HashSet::from([session_jwt]));

        let stored = handler.get_jwt_blacklist().await.unwrap();
        assert!(stored.contains(&session_jwt));
        assert!(
            !stored.contains(&grant_jwt),
            "logout must not blacklist access tokens issued from an app-cli grant"
        );
        assert_eq!(
            handler.check_refresh_token(grant_hash, &user).await.unwrap().0,
            true
        );
    }

    /// Uninstall is a retry path, so revoking a grant that is already gone has
    /// to be a no-op rather than an error.
    #[tokio::test]
    #[serial]
    async fn revoking_a_missing_grant_is_a_no_op() {
        let handler = new_handler().await;
        let user = UserId::new(TEST_USER);
        let (_, _, hash) = handler
            .create_refresh_token_with(
                &user,
                0,
                Duration::days(3650),
                REFRESH_TOKEN_KIND_APP_CLI,
                None,
            )
            .await
            .unwrap();

        assert_eq!(handler.delete_refresh_token(hash).await.unwrap(), 1);
        assert_eq!(handler.delete_refresh_token(hash).await.unwrap(), 0);
        assert!(handler
            .blacklist_jwts_by_refresh_token(hash)
            .await
            .unwrap()
            .is_empty());
    }
}
