use crate::domain::{error::Result, types::UserId};
use async_trait::async_trait;

pub use lldap_auth::{login, registration};

#[async_trait]
pub trait OpaqueHandler: Send + Sync {
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse>;
    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId>;
    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse>;
    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<()>;

    async fn registration_password(
        &self,
        //request: registration::ClientSimpleRegisterRequest,
        username: &UserId,
        password: String,
    ) -> Result<()>;
}

#[cfg(test)]
mockall::mock! {
    pub TestOpaqueHandler{}
    impl Clone for TestOpaqueHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl OpaqueHandler for TestOpaqueHandler {
        async fn login_start(
            &self,
            request: login::ClientLoginStartRequest
        ) -> Result<login::ServerLoginStartResponse>;
        async fn login_finish(&self, request: login::ClientLoginFinishRequest ) -> Result<UserId>;
        async fn registration_start(
            &self,
            request: registration::ClientRegistrationStartRequest
        ) -> Result<registration::ServerRegistrationStartResponse>;
        async fn registration_finish(
            &self,
            request: registration::ClientRegistrationFinishRequest
        ) -> Result<()>;
    }
}
