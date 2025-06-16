use async_nats::ConnectOptions;
use log::info;
use std::env;

pub async fn publish_nats_event(
    subject: String,
    event: serde_json::Value,
) -> Result<(), anyhow::Error> {
    let nats_user = env::var("NATS_USERNAME").unwrap_or_else(|_| "unknown".to_string());
    let nats_password = env::var("NATS_PASSWORD").unwrap_or_else(|_| "unknown".to_string());
    let nats_host = env::var("NATS_HOST").unwrap_or_else(|_| "nats".to_string());
    let nats_port = env::var("NATS_PORT").unwrap_or_else(|_| "4222".to_string());
    let nats_url = format!("nats://{nats_host}:{nats_port}");

    let client = ConnectOptions::new()
        .user_and_password(nats_user, nats_password)
        .connect(nats_url)
        .await?;
    let js = async_nats::jetstream::new(client);
    let publish_result = js
        .publish(
            subject.clone(),
            serde_json::to_string(&event).unwrap_or_default().into(),
        )
        .await?;
    publish_result.await?;
    info!("Published event: {} to nats subject: {}", event, subject);
    Ok(())
}
