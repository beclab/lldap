use super::tcp_backend_handler::TcpBackendHandler;
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
    ) -> Result<(String, chrono::Duration)> {
        debug!(?user);
        // TODO: Initialize the rng only once. Maybe Arc<Cell>?
        let refresh_token = gen_random_string(100);
        let refresh_token_hash = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut s = DefaultHasher::new();
            refresh_token.hash(&mut s);
            s.finish()
        };
        let duration = chrono::Duration::days(jwt_refresh_token_expiry_days);
        let duration = chrono::Duration::minutes(20);

        let new_token = model::jwt_refresh_storage::Model {
            refresh_token_hash: refresh_token_hash as i64,
            user_id: user.clone(),
            expiry_date: chrono::Utc::now().naive_utc() + duration,
            mfa: mfa,
        }
        .into_active_model();
        new_token.insert(&self.sql_pool).await?;
        Ok((refresh_token, duration))
    }

    #[instrument(skip_all, level = "debug")]
    async fn register_jwt(
        &self,
        user: &UserId,
        jwt_hash: u64,
        token: &str,
        expiry_date: NaiveDateTime,
        mfa: i64,
    ) -> Result<()> {
        debug!(?user, ?jwt_hash);
        let new_token = model::jwt_storage::Model {
            jwt_hash: jwt_hash as i64,
            token: token.to_string(),
            user_id: user.clone(),
            blacklisted: false,
            expiry_date,
            mfa,
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
    async fn check_token(&self, refresh_token_hash: u64, user: &UserId) -> Result<(bool, i64)> {
        debug!(?user);

        let record = model::JwtRefreshStorage::find_by_id(refresh_token_hash as i64)
            .filter(JwtRefreshStorageColumn::UserId.eq(user))
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
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> Result<()> {
        model::JwtRefreshStorage::delete_by_id(refresh_token_hash as i64)
            .exec(&self.sql_pool)
            .await?;
        Ok(())
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
