use juniper::{FieldError, Value};

pub fn create_custom_error(code: i32, reason: &str, message: &str) -> FieldError {
    FieldError::new(
        message,
        Value::Object(
            vec![
                ("status".to_string(), Value::scalar("failure".to_string())),
                ("code".to_string(), Value::scalar(code)),
                ("message".to_string(), Value::scalar(message.to_string())),
                ("reason".to_string(), Value::scalar(reason.to_string())),
            ]
            .into_iter()
            .collect(),
        ),
    )
}
