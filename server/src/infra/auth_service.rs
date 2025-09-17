use actix_web::{
    cookie::{Cookie, SameSite},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    error::{ErrorBadRequest, ErrorUnauthorized},
    web, HttpRequest, HttpResponse,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use anyhow::{anyhow, Result};
use chrono::prelude::*;
use futures::future::{ok, Ready};
use futures_util::FutureExt;
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use rand::Rng;
use serde_json::json;
use sha2::Sha512;
use std::{
    collections::HashSet,
    hash::Hash,
    pin::Pin,
    task::{Context, Poll},
};
use time::ext::NumericalDuration;
use tracing::{debug, error, info, instrument, warn};

macro_rules! errorf {
    ($($arg:tt)*) => {
        error!(file = file!(), line = line!(), $($arg)*)
    };
}

use crate::{
    domain::{
        error::DomainError,
        handler::{BackendHandler, BindRequest, LoginHandler, UserRequestFilter},
        opaque_handler::OpaqueHandler,
        types::{GroupDetails, GroupName, UserColumn, UserId},
    },
    infra::{
        access_control::{ReadonlyBackendHandler, UserReadableBackendHandler, ValidationResults},
        tcp_backend_handler::*,
        tcp_server::{error_to_http_response, AppState, TcpError, TcpResult},
    },
};
use lldap_auth::{login, password_reset, registration, JWTClaims};
use rand::thread_rng;

type Token<S> = jwt::Token<jwt::Header, JWTClaims, S>;
type SignedToken = Token<jwt::token::Signed>;

#[derive(Debug)]
pub struct LoginRecord {
    pub user_id: UserId,
    pub success: bool,
    pub reason: String,
    pub source_ip: String,
    pub user_agent: String,
}

fn default_hash<T: Hash + ?Sized>(token: &T) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    let mut s = DefaultHasher::new();
    token.hash(&mut s);
    s.finish()
}

async fn create_jwt<Handler: TcpBackendHandler>(
    handler: &Handler,
    key: &Hmac<Sha512>,
    user: &UserId,
    groups: HashSet<GroupDetails>,
    mfa: i64,
    jwt_token_expiry_days: i64,
) -> SignedToken {
    let exp_utc = Utc::now() + chrono::Duration::days(jwt_token_expiry_days);
    let claims = JWTClaims {
        exp: exp_utc.timestamp(),
        iat: Utc::now().timestamp(),
        username: user.to_string(),
        groups: groups
            .into_iter()
            .map(|g| g.display_name.into_string())
            .collect(),
        mfa: mfa,
        jid: thread_rng().gen::<u64>(),
    };
    let expiry = exp_utc.naive_utc();
    let header = jwt::Header {
        algorithm: jwt::AlgorithmType::Hs512,
        ..Default::default()
    };
    let token = jwt::Token::new(header, claims).sign_with_key(key).unwrap();
    handler
        .register_jwt(
            user,
            default_hash(token.as_str()),
            token.as_str(),
            expiry,
            mfa,
        )
        .await
        .unwrap();
    token
}

fn parse_refresh_token(token: &str) -> TcpResult<(u64, UserId)> {
    match token.split_once('+') {
        None => Err(DomainError::AuthenticationError("Invalid refresh token".to_string()).into()),
        Some((token, u)) => Ok((default_hash(token), UserId::new(u))),
    }
}

fn get_refresh_token(request: HttpRequest) -> TcpResult<(u64, UserId)> {
    match (
        request.cookie("refresh_token"),
        request.headers().get("refresh-token"),
    ) {
        (Some(c), _) => parse_refresh_token(c.value()),
        (_, Some(t)) => parse_refresh_token(t.to_str().unwrap()),
        (None, None) => {
            error!("No refresh token found in cookie[refresh_token] or headers[refresh-token]");
            Err(DomainError::AuthenticationError("Missing refresh token".to_string()).into())
        }
    }
}

#[instrument(skip_all, level = "debug")]
async fn get_refresh<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let jwt_key = &data.jwt_key;
    let (refresh_token_hash, user) = get_refresh_token(request)?;
    let (found, mfa) = data
        .get_tcp_handler()
        .check_refresh_token(refresh_token_hash, &user)
        .await?;
    if !found {
        errorf!(
            "Refresh token not found, refresh_token_hash: {}",
            refresh_token_hash
        );
        return Err(TcpError::DomainError(DomainError::AuthenticationError(
            "Invalid refresh token".to_string(),
        )));
    }
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    let groups = data.get_readonly_handler().get_user_groups(&user).await?;
    let token = create_jwt(
        data.get_tcp_handler(),
        jwt_key,
        &user,
        groups,
        mfa,
        data.jwt_token_expiry_days,
    )
    .await;
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(1.days())
                .path(&path)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .json(&login::ServerLoginResponse {
            token: token.as_str().to_owned(),
            refresh_token: None,
        }))
}

async fn get_refresh_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_refresh(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_password_reset_step1<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<()>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let user_string = request
        .match_info()
        .get("user_id")
        .ok_or_else(|| TcpError::BadRequest("Missing user ID".to_string()))?;
    let user_results = data
        .get_readonly_handler()
        .list_users(
            Some(UserRequestFilter::Or(vec![
                UserRequestFilter::UserId(UserId::new(user_string)),
                UserRequestFilter::Equality(UserColumn::Email, user_string.to_owned()),
            ])),
            false,
        )
        .await?;
    if user_results.is_empty() {
        return Ok(());
    } else if user_results.len() > 1 {
        return Err(TcpError::InternalServerError(
            "Ambiguous user id or email".to_owned(),
        ));
    }
    let user = &user_results[0].user;
    let token = match data
        .get_tcp_handler()
        .start_password_reset(&user.user_id)
        .await?
    {
        None => return Ok(()),
        Some(token) => token,
    };
    if let Err(e) = super::mail::send_password_reset_email(
        user.display_name
            .as_deref()
            .unwrap_or_else(|| user.user_id.as_str()),
        user.email.as_str(),
        &token,
        &data.server_url,
        &data.mail_options,
    )
    .await
    {
        warn!("Error sending email: {:#?}", e);
        info!("Reset token: {}", token);
        return Err(TcpError::InternalServerError(format!(
            "Could not send email: {}",
            e
        )));
    }
    Ok(())
}

async fn get_password_reset_step1_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_password_reset_step1(data, request)
        .await
        .map(|()| HttpResponse::Ok().finish())
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_password_reset_step2<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let token = request
        .match_info()
        .get("token")
        .ok_or_else(|| TcpError::BadRequest("Missing reset token".to_owned()))?;
    let user_id = data
        .get_tcp_handler()
        .get_user_id_for_password_reset_token(token)
        .await
        .map_err(|e| {
            debug!("Reset token error: {e:#}");
            TcpError::NotFoundError("Wrong or expired reset token".to_owned())
        })?;
    let _ = data
        .get_tcp_handler()
        .delete_password_reset_token(token)
        .await;
    let groups = HashSet::new();
    let token = create_jwt(
        data.get_tcp_handler(),
        &data.jwt_key,
        &user_id,
        groups,
        0,
        data.jwt_token_expiry_days,
    )
    .await;
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(5.minutes())
                // Cookie is only valid to reset the password.
                .path(format!("{}auth", path))
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .json(&password_reset::ServerPasswordResetResponse {
            user_id: user_id.to_string(),
            token: token.as_str().to_owned(),
        }))
}

async fn get_password_reset_step2_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_password_reset_step2(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

async fn totp_bind_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    payload: web::Payload,
    http_request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    totp_bind(data, payload, http_request)
        .await
        .unwrap_or_else(error_to_http_response)
}

async fn token_list_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    token_list(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

async fn token_list<Backend>(
    data: web::Data<AppState<Backend>>,
    http_request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    // let auth_header = http_request
    //     .headers()
    //     .get("Authorization")
    //     .and_then(|h| h.to_str().ok())
    //     .and_then(|h| h.strip_prefix("Bearer "))
    //     .ok_or_else(|| {
    //         TcpError::UnauthorizedError("Missing or invalid authorization header".to_string())
    //     })?;
    //
    // let validation_result = check_if_token_is_valid(&data, auth_header)
    //     .map_err(|_| TcpError::UnauthorizedError("Invalid token".to_string()))?;

    // let user_id = &validation_result.user;
    // let user_is_admin = data
    //     .get_readonly_handler()
    //     .get_user_groups(&user_id)
    //     .await?
    //     .iter()
    //     .any(|g| g.display_name == "lldap_admin".into());
    // if !user_is_admin {
    //     return Err(TcpError::UnauthorizedError(
    //         "only admin user can list access token".to_owned(),
    //     ));
    // }

    let tokens = data.get_tcp_handler().access_token_list().await?;
    Ok(HttpResponse::Ok().json(tokens))
}

async fn access_token_verify_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::TokenVerifyRequest>,
    http_request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    match access_token_verify(data, request, http_request).await {
        Ok(claims) => HttpResponse::Ok().json(claims),
        Err(err) => HttpResponse::BadRequest().json(err.to_string()),
    }
}

async fn access_token_verify<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::TokenVerifyRequest>,
    http_request: HttpRequest,
) -> Result<JWTClaims>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let login::TokenVerifyRequest { access_token } = request.into_inner();

    let token: Token<_> =
        VerifyWithKey::verify_with_key(access_token.clone().as_str(), &data.jwt_key).map_err(
            |_| {
                errorf!("invalid jwt access_token: {}", access_token.as_str());
                anyhow!("access_token verify invalid JWT")
            },
        )?;

    let naive_datetime: NaiveDateTime =
        NaiveDateTime::from_timestamp_opt(token.claims().exp, 0).unwrap();
    let exp_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
    if exp_utc.lt(&Utc::now()) {
        errorf!("expired token: {}", access_token.as_str());
        return Err(anyhow!("Expired JWT"));
    }
    if token.header().algorithm != jwt::AlgorithmType::Hs512 {
        return Err(anyhow!(format!(
            "Unsupported JWT algorithm: '{:?}'. Supported ones are: ['HS512']",
            token.header().algorithm
        )));
    }
    let jwt_hash = default_hash(access_token.as_str());
    if data.jwt_blacklist.read().unwrap().contains(&jwt_hash) {
        errorf!("blacklisted token: {}", access_token.as_str());
        return Err(anyhow!("JWT was logged out"));
    }
    Ok(token.claims().clone())
}

async fn totp_bind<Backend>(
    data: web::Data<AppState<Backend>>,
    payload: web::Payload,
    http_request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    use actix_web::FromRequest;
    let inner_payload = &mut payload.into_inner();
    let validation_result = BearerAuth::from_request(&http_request, inner_payload)
        .await
        .ok()
        .and_then(|bearer| check_if_token_is_valid(&data, bearer.token()).ok())
        .ok_or_else(|| {
            errorf!("totp_bind invalid token");
            TcpError::UnauthorizedError("invalid token to bind".to_string())
        })?;
    let user_id = &validation_result.user;
    let user_totp = data
        .get_tcp_handler()
        .get_user_totp_secret(&user_id)
        .await?;
    if let Some(totp_secret) = user_totp.totp_secret {
        // let issuer = "lldap";
        // let otp_auth_url = format!("otpauth://totp{}:{}?secret={}&issuer={}",
        //                            issuer,user_id.as_str(),totp_secret, issuer
        // );
        return Ok(HttpResponse::Ok().json(json!({
            "base32_secret": totp_secret
        })));
    }

    let mut rng = rand::thread_rng();
    let secret: [u8; 32] = rng.gen();

    let totp = totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30, secret.to_vec()).unwrap();
    let base32_secret = totp.get_secret_base32();

    data.get_tcp_handler()
        .update_user_totp_secret(&user_id, base32_secret.clone())
        .await?;

    // let issuer = "lldap";
    // let otp_auth_url = format!("otpauth://totp{}:{}?secret={}&issuer={}",
    //                            issuer,user_id.as_str(),base32_secret, issuer
    // );
    Ok(HttpResponse::Ok().json(json!({
        "base32_secret":base32_secret,
    })))
}

async fn totp_verify_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    // payload: web::Payload,
    request: web::Json<login::TotpVerifyRequest>,
    http_request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    totp_verify(data, request, http_request)
        .await
        .unwrap_or_else(error_to_http_response)
}

async fn totp_verify<Backend>(
    data: web::Data<AppState<Backend>>,
    // payload: web::Payload,
    request: web::Json<login::TotpVerifyRequest>,
    http_request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let auth_header = http_request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            TcpError::UnauthorizedError("Missing or invalid authorization header".to_string())
        })?;

    let validation_result = check_if_token_is_valid(&data, auth_header).map_err(|_| {
        errorf!("invalid token: {}", auth_header);
        TcpError::UnauthorizedError("Invalid token".to_string())
    })?;
    let user_id = &validation_result.user;
    let user_totp = data
        .get_tcp_handler()
        .get_user_totp_secret(&user_id)
        .await?;
    let totp_secret = match user_totp.totp_secret {
        Some(totp_secret) => totp_secret,
        None => {
            return {
                errorf!("no totp secret found for user: {}", user_id);
                Err(TcpError::NotFoundError("no totp secret found".to_owned()))
            }
        }
    };
    let totp = match totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(totp_secret).to_bytes().unwrap(),
    ) {
        Ok(totp) => totp,
        Err(_e) => {
            errorf!(
                "failed to create totp instance for user: {},err: {}",
                user_id,
                _e
            );
            return Err(TcpError::NotFoundError(
                "totp not configured for this user".to_owned(),
            ));
        }
    };
    let login::TotpVerifyRequest { token } = request.into_inner();

    let is_valid = totp.check_current(&token).unwrap_or(false);
    if !is_valid {
        return Ok(
            HttpResponse::BadRequest().json(json!({"status":"KO","message":"Invalid token"}))
        );
    }
    let groups = data
        .get_readonly_handler()
        .get_user_groups(&user_id)
        .await?;

    let (refresh_token, max_age) = data
        .get_tcp_handler()
        .create_refresh_token(&user_id, 1, data.jwt_refresh_token_expiry_days)
        .await?;
    let token = create_jwt(
        data.get_tcp_handler(),
        &data.jwt_key,
        &user_id,
        groups,
        1,
        data.jwt_token_expiry_days,
    )
    .await;
    let refresh_token_plus_name = refresh_token + "+" + user_id.as_str();

    Ok(HttpResponse::Ok().json(&login::ServerLoginResponse {
        token: token.as_str().to_owned(),
        refresh_token: Some(refresh_token_plus_name),
    }))
}

async fn get_sign_token_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    http_request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_sign_token(data, http_request)
        .await
        .unwrap_or_else(error_to_http_response)
}

async fn get_sign_token<Backend>(
    data: web::Data<AppState<Backend>>,
    http_request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let auth_header = http_request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            errorf!("missing authorization header");
            TcpError::UnauthorizedError("Missing or invalid authorization header".to_string())
        })?;

    let validation_result = check_if_token_is_valid(&data, auth_header).map_err(|_| {
        errorf!("invalid token: {}", auth_header);
        TcpError::UnauthorizedError("Invalid token".to_string())
    })?;
    let user_id = &validation_result.user;
    let groups = data
        .get_readonly_handler()
        .get_user_groups(&user_id)
        .await?;

    let (refresh_token, max_age) = data
        .get_tcp_handler()
        .create_refresh_token(&user_id, 1, data.jwt_refresh_token_expiry_days)
        .await?;
    let token = create_jwt(
        data.get_tcp_handler(),
        &data.jwt_key,
        &user_id,
        groups,
        1,
        data.jwt_token_expiry_days,
    )
    .await;
    let refresh_token_plus_name = refresh_token + "+" + user_id.as_str();

    Ok(HttpResponse::Ok().json(&login::ServerLoginResponse {
        token: token.as_str().to_owned(),
        refresh_token: Some(refresh_token_plus_name),
    }))
}

#[instrument(skip_all, level = "debug")]
async fn get_logout<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let (refresh_token_hash, user) = get_refresh_token(request)?;
    data.get_tcp_handler()
        .delete_refresh_token(refresh_token_hash)
        .await?;
    let new_blacklisted_jwt_hashes = data.get_tcp_handler().blacklist_jwts(&user).await?;
    let mut jwt_blacklist = data.jwt_blacklist.write().unwrap();
    for jwt_hash in new_blacklisted_jwt_hashes {
        jwt_blacklist.insert(jwt_hash);
    }
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", "")
                .max_age(0.days())
                .path(&path)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .cookie(
            Cookie::build("refresh_token", "")
                .max_age(0.days())
                .path(format!("{}auth", path))
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .finish())
}

async fn get_logout_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_logout(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

pub(crate) fn error_to_api_response<T, E: Into<TcpError>>(error: E) -> ApiResult<T> {
    ApiResult::Right(error_to_http_response(error.into()))
}

pub type ApiResult<M> = actix_web::Either<web::Json<M>, HttpResponse>;

#[instrument(skip_all, level = "debug")]
async fn opaque_login_start<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginStartRequest>,
) -> ApiResult<login::ServerLoginStartResponse>
where
    Backend: OpaqueHandler + 'static,
{
    data.get_opaque_handler()
        .login_start(request.into_inner())
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_login_successful_response<Backend>(
    data: &web::Data<AppState<Backend>>,
    name: &UserId,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler,
{
    // The authentication was successful, we need to fetch the groups to create the JWT
    // token.
    let groups = data.get_readonly_handler().get_user_groups(name).await?;
    let (refresh_token, max_age) = data
        .get_tcp_handler()
        .create_refresh_token(name, 0, data.jwt_refresh_token_expiry_days)
        .await?;
    let token = create_jwt(
        data.get_tcp_handler(),
        &data.jwt_key,
        name,
        groups,
        0,
        data.jwt_token_expiry_days,
    )
    .await;
    let refresh_token_plus_name = refresh_token + "+" + name.as_str();
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(1.days())
                .path(&path)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .cookie(
            Cookie::build("refresh_token", refresh_token_plus_name.clone())
                .max_age(max_age.num_days().days())
                .path(format!("{}auth", path))
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .json(&login::ServerLoginResponse {
            token: token.as_str().to_owned(),
            refresh_token: Some(refresh_token_plus_name),
        }))
}

#[instrument(skip_all, level = "debug")]
async fn opaque_login_finish<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginFinishRequest>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    let name = data
        .get_opaque_handler()
        .login_finish(request.into_inner())
        .await?;
    get_login_successful_response(&data, &name).await
}

async fn opaque_login_finish_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginFinishRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    opaque_login_finish(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn simple_login<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientSimpleLoginRequest>,
    http_request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    let login::ClientSimpleLoginRequest { username, password } = request.into_inner();
    let bind_request = BindRequest {
        name: username.clone(),
        password,
    };
    let source_ip = http_request
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();
    let user_agent = http_request
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let bind_result = data.get_login_handler().bind(bind_request).await;

    let mut record = LoginRecord {
        user_id: username.clone(),
        success: true,
        reason: "authenticated successfully".to_string(),
        source_ip: source_ip,
        user_agent: user_agent,
    };

    match bind_result {
        Ok(_) => {
            if let Err(e) = data.get_tcp_handler().create_login_record(&record).await {
                error!("failed to create login record: {}", e);
            }
            get_login_successful_response(&data, &username).await
        }
        Err(e) => {
            record.success = false;
            record.reason = format!("{}", e);
            if let Err(e) = data.get_tcp_handler().create_login_record(&record).await {
                error!("failed to create login record: {}", e);
            }
            return Err(e.into());
        }
    }
}

async fn simple_login_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientSimpleLoginRequest>,
    http_request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    simple_login(data, request, http_request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn simple_register<Backend>(
    data: web::Data<AppState<Backend>>,
    payload: actix_web::web::Payload,
    request: actix_web::HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    use actix_web::FromRequest;
    let inner_payload = &mut payload.into_inner();
    let validation_result = BearerAuth::from_request(&request, inner_payload)
        .await
        .ok()
        .and_then(|bearer| check_if_token_is_valid(&data, bearer.token()).ok())
        .ok_or_else(|| {
            TcpError::UnauthorizedError("Not authorized to change the user's password".to_string())
        })?;
    let registration_start_request =
        web::Json::<registration::ClientSimpleRegisterRequest>::from_request(
            &request,
            inner_payload,
        )
        .await
        .map_err(|e| TcpError::BadRequest(format!("{:#?}", e)))?
        .into_inner();

    let user_id = &registration_start_request.username;
    let user_is_admin = data
        .get_readonly_handler()
        .get_user_groups(user_id)
        .await?
        .iter()
        .any(|g| g.display_name == "lldap_admin".into());
    if !validation_result.can_change_password(user_id, user_is_admin) {
        errorf!(
            "user {} is not authorized to change the user's password",
            user_id
        );
        return Err(TcpError::UnauthorizedError(
            "Not authorized to change the user's password".to_string(),
        ));
    }

    let pass_length = registration_start_request.password.len();
    assert!(
        pass_length >= 8,
        "Minimum password length is 8 characters, got {} characters",
        pass_length
    );

    data.get_opaque_handler()
        .registration_password(
            &registration_start_request.username,
            registration_start_request.password.to_string(),
        )
        .await?;
    data.get_tcp_handler()
        .set_user_initialized(&registration_start_request.username)
        .await?;
    
    // Delete all refresh tokens for this user after setting password
    if let Err(e) = data.get_tcp_handler()
        .delete_refresh_token_by_user(&registration_start_request.username)
        .await
    {
        errorf!("failed to delete refresh tokens for user {}: {}", registration_start_request.username, e);
        // Continue execution even if refresh token deletion fails
    }
    
    // Blacklist all JWT tokens for this user after setting password
    match data.get_tcp_handler().blacklist_jwts(&registration_start_request.username).await {
        Ok(new_blacklisted_jwt_hashes) => {
            let mut jwt_blacklist = data.jwt_blacklist.write().unwrap();
            for jwt_hash in new_blacklisted_jwt_hashes {
                jwt_blacklist.insert(jwt_hash);
            }
        }
        Err(e) => {
            errorf!("failed to blacklist JWT tokens for user {}: {}", registration_start_request.username, e);
            // Continue execution even if JWT blacklisting fails
        }
    }
    
    get_login_successful_response(&data, &registration_start_request.username).await
}

async fn simple_register_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    payload: actix_web::web::Payload,
    request: actix_web::HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    simple_register(data, payload, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug", fields(name = %request.name))]
async fn post_authorize<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<BindRequest>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + 'static,
{
    let name = request.name.clone();
    data.get_login_handler().bind(request.into_inner()).await?;
    get_login_successful_response(&data, &name).await
}

async fn post_authorize_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<BindRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + 'static,
{
    post_authorize(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn opaque_register_start<Backend>(
    request: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> TcpResult<registration::ServerRegistrationStartResponse>
where
    Backend: BackendHandler + OpaqueHandler + 'static,
{
    use actix_web::FromRequest;
    let inner_payload = &mut payload.into_inner();
    let validation_result = BearerAuth::from_request(&request, inner_payload)
        .await
        .ok()
        .and_then(|bearer| check_if_token_is_valid(&data, bearer.token()).ok())
        .ok_or_else(|| {
            TcpError::UnauthorizedError("Not authorized to change the user's password".to_string())
        })?;
    let registration_start_request =
        web::Json::<registration::ClientRegistrationStartRequest>::from_request(
            &request,
            inner_payload,
        )
        .await
        .map_err(|e| TcpError::BadRequest(format!("{:#?}", e)))?
        .into_inner();
    let user_id = &registration_start_request.username;
    let user_is_admin = data
        .get_readonly_handler()
        .get_user_groups(user_id)
        .await?
        .iter()
        .any(|g| g.display_name == "lldap_admin".into());
    if !validation_result.can_change_password(user_id, user_is_admin) {
        return Err(TcpError::UnauthorizedError(
            "Not authorized to change the user's password".to_string(),
        ));
    }
    Ok(data
        .get_opaque_handler()
        .registration_start(registration_start_request)
        .await?)
}

async fn opaque_register_start_handler<Backend>(
    request: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> ApiResult<registration::ServerRegistrationStartResponse>
where
    Backend: BackendHandler + OpaqueHandler + 'static,
{
    opaque_register_start(request, payload, data)
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

#[instrument(skip_all, level = "debug")]
async fn opaque_register_finish<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<registration::ClientRegistrationFinishRequest>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    data.get_opaque_handler()
        .registration_finish(request.into_inner())
        .await?;
    Ok(HttpResponse::Ok().finish())
}

async fn opaque_register_finish_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<registration::ClientRegistrationFinishRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    opaque_register_finish(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

pub struct CookieToHeaderTranslatorFactory;

impl<S> Transform<S, ServiceRequest> for CookieToHeaderTranslatorFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = actix_web::Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = CookieToHeaderTranslator<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CookieToHeaderTranslator { service })
    }
}

pub struct CookieToHeaderTranslator<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for CookieToHeaderTranslator<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = actix_web::Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn core::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        if let Some(token_cookie) = req.cookie("token") {
            if let Ok(header_value) = actix_http::header::HeaderValue::from_str(&format!(
                "Bearer {}",
                token_cookie.value()
            )) {
                req.headers_mut()
                    .insert(actix_http::header::AUTHORIZATION, header_value);
            } else {
                return async move {
                    Ok(req.error_response(ErrorBadRequest("Invalid token cookie")))
                }
                .boxed_local();
            }
        };

        Box::pin(self.service.call(req))
    }
}

#[instrument(skip_all, level = "debug", err, ret)]
pub(crate) fn check_if_token_is_valid<Backend: BackendHandler>(
    state: &AppState<Backend>,
    token_str: &str,
) -> Result<ValidationResults, actix_web::Error> {
    let token: Token<_> =
        VerifyWithKey::verify_with_key(token_str, &state.jwt_key).map_err(|_| {
            errorf!("Invalid JWT token: {}", token_str);
            ErrorUnauthorized("Invalid JWT")
        })?;
    let naive_datetime: NaiveDateTime =
        NaiveDateTime::from_timestamp_opt(token.claims().exp, 0).unwrap();
    let exp_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
    if exp_utc.lt(&Utc::now()) {
        errorf!("Token expired: {}", token_str);
        return Err(ErrorUnauthorized("Expired JWT"));
    }
    if token.header().algorithm != jwt::AlgorithmType::Hs512 {
        return Err(ErrorUnauthorized(format!(
            "Unsupported JWT algorithm: '{:?}'. Supported ones are: ['HS512']",
            token.header().algorithm
        )));
    }
    let jwt_hash = default_hash(token_str);
    if state.jwt_blacklist.read().unwrap().contains(&jwt_hash) {
        errorf!("JWT was logged out: {}", token_str);
        return Err(ErrorUnauthorized("JWT was logged out"));
    }
    Ok(state.backend_handler.get_permissions_from_groups(
        UserId::new(&token.claims().username),
        token
            .claims()
            .groups
            .iter()
            .map(|s| GroupName::from(s.as_str())),
    ))
}

async fn access_token_invalidate_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::TokenInvalidateRequest>,
    http_request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    match access_token_invalidate(data, request, http_request).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) => HttpResponse::BadRequest().body(err.to_string()),
    }
}

async fn access_token_invalidate<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::TokenInvalidateRequest>,
    http_request: HttpRequest,
) -> Result<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let login::TokenInvalidateRequest { access_token } = request.into_inner();
    let token: Token<_> = VerifyWithKey::verify_with_key(access_token.as_str(), &data.jwt_key)
        .map_err(|_| anyhow!("access_token invalidate invalid JWT"))?;

    let naive_datetime: NaiveDateTime = NaiveDateTime::from_timestamp_opt(token.claims().exp, 0)
        .ok_or_else(|| anyhow!("Invalid expiration time"))?;
    let exp_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
    if exp_utc.lt(&Utc::now()) {
        return Ok(HttpResponse::Ok().finish());
    }

    let jwt_hash = default_hash(&access_token);
    if data.jwt_blacklist.read().unwrap().contains(&jwt_hash) {
        return Ok(HttpResponse::Ok().finish());
    }

    data.jwt_blacklist.write().unwrap().insert(jwt_hash);
    Ok(HttpResponse::Ok().finish())
}

async fn revoke_user_tokens_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    http_request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    revoke_user_tokens(data, http_request)
        .await
        .unwrap_or_else(error_to_http_response)
}
#[instrument(skip_all, level = "debug")]
async fn revoke_user_tokens<Backend>(
    data: web::Data<AppState<Backend>>,
    http_request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let username = http_request
        .match_info()
        .get("user")
        .ok_or_else(|| TcpError::BadRequest("missing user".to_owned()))?;
    let target_user_id = UserId::new(&username);

    let auth_header = http_request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            errorf!("Missing Authorization header");
            TcpError::UnauthorizedError("Missing or invalid authorization header".to_string())
        })?;
    let validation_request = check_if_token_is_valid(&data, auth_header).map_err(|_| {
        errorf!("Invalid authorization header: {}", auth_header);
        TcpError::UnauthorizedError("Invalid token for revoke user token".to_owned())
    })?;
    let user_id = &validation_request.user;

    let user_is_admin = data
        .get_readonly_handler()
        .get_user_groups(user_id)
        .await?
        .iter()
        .any(|g| g.display_name == "lldap_admin".into());
    if !validation_request.can_change_password(user_id, user_is_admin) {
        errorf!("user {} is not authorized to revoke user token", user_id);
        return Err(TcpError::UnauthorizedError(
            "Not authorized to revoke user token".to_owned(),
        ));
    }

    let user_exists = data
        .get_readonly_handler()
        .list_users(
            Some(UserRequestFilter::UserId(target_user_id.clone())),
            false,
        )
        .await?
        .len()
        > 0;
    if !user_exists {
        errorf!("user {} is not found", target_user_id);
        return Err(TcpError::NotFoundError(format!(
            "User '{}' not found",
            target_user_id
        )));
    }
    data.get_tcp_handler()
        .delete_refresh_token_by_user(user_id)
        .await?;

    let new_blacklisted_jwt_hashes = data
        .get_tcp_handler()
        .blacklist_jwts(&target_user_id)
        .await?;
    let mut jwt_blacklist = data.jwt_blacklist.write().unwrap();
    for jwt_hash in new_blacklisted_jwt_hashes {
        jwt_blacklist.insert(jwt_hash);
    }
    Ok(HttpResponse::Ok().finish())
}

#[instrument(skip_all, level = "debug")]
async fn verify_user_credentials<Backend>(
    data: &web::Data<AppState<Backend>>,
    username: UserId,
    password: String,
) -> TcpResult<bool>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    let bind_request = BindRequest {
        name: username.clone(),
        password,
    };

    match data.get_login_handler().bind(bind_request).await {
        Ok(_) => {
            debug!("User credentials verified successfully for: {}", username);
            Ok(true)
        }
        Err(e) => {
            debug!(
                "User credentials verification failed for {}: {}",
                username, e
            );
            Ok(false)
        }
    }
}

async fn verify_user_credentials_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientSimpleLoginRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    let login::ClientSimpleLoginRequest { username, password } = request.into_inner();

    match verify_user_credentials(&data, username.clone(), password).await {
        Ok(is_valid) => HttpResponse::Ok().json(serde_json::json!({
            "username": username.as_str(),
            "valid": is_valid,
            "message": if is_valid { "Credentials are valid" } else { "Invalid credentials" }
        })),
        Err(e) => {
            error!("Error verifying user credentials: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error during credential verification"
            }))
        }
    }
}

pub fn configure_server<Backend>(cfg: &mut web::ServiceConfig, enable_password_reset: bool)
where
    Backend: TcpBackendHandler + LoginHandler + OpaqueHandler + BackendHandler + 'static,
{
    cfg.service(web::resource("").route(web::post().to(post_authorize_handler::<Backend>)))
        .service(
            web::resource("/opaque/login/start")
                .route(web::post().to(opaque_login_start::<Backend>)),
        )
        .service(
            web::resource("/opaque/login/finish")
                .route(web::post().to(opaque_login_finish_handler::<Backend>)),
        )
        .service(
            web::resource("/simple/login").route(web::post().to(simple_login_handler::<Backend>)),
        )
        .service(web::resource("/refresh").route(web::get().to(get_refresh_handler::<Backend>)))
        .service(web::resource("/logout").route(web::get().to(get_logout_handler::<Backend>)))
        .service(
            web::resource("/simple/register")
                .route(web::post().to(simple_register_handler::<Backend>)),
        )
        .service(
            web::scope("/opaque/register")
                .wrap(CookieToHeaderTranslatorFactory)
                .service(
                    web::resource("/start")
                        .route(web::post().to(opaque_register_start_handler::<Backend>)),
                )
                .service(
                    web::resource("/finish")
                        .route(web::post().to(opaque_register_finish_handler::<Backend>)),
                ),
        )
        .service(
            web::scope("/totp")
                .service(web::resource("/bind").route(web::post().to(totp_bind_handler::<Backend>)))
                .service(
                    web::resource("/verify").route(web::post().to(totp_verify_handler::<Backend>)),
                ),
        )
        .service(
            web::resource("/sign/token").route(web::post().to(get_sign_token_handler::<Backend>)),
        )
        .service(web::resource("/token/list").route(web::get().to(token_list_handler::<Backend>)))
        .service(
            web::resource("/token/verify")
                .route(web::post().to(access_token_verify_handler::<Backend>)),
        )
        .service(
            web::resource("/token/invalidate")
                .route(web::post().to(access_token_invalidate_handler::<Backend>)),
        )
        .service(
            web::resource("/revoke/{user}/token")
                .route(web::post().to(revoke_user_tokens_handler::<Backend>)),
        )
        .service(
            web::resource("/credentials/verify")
                .route(web::post().to(verify_user_credentials_handler::<Backend>)),
        );

    if enable_password_reset {
        cfg.service(
            web::resource("/reset/step1/{user_id}")
                .route(web::post().to(get_password_reset_step1_handler::<Backend>)),
        )
        .service(
            web::resource("/reset/step2/{token}")
                .route(web::get().to(get_password_reset_step2_handler::<Backend>)),
        );
    }
}
