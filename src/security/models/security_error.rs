use std::time::SystemTimeError;

pub enum SecurityErrors{
    Unauthorized(String),
    Forbidden(String),
    MissingAuthorizationHeader(String),
    GenericError(String),
}
impl From<jsonwebtoken::errors::Error> for SecurityErrors{
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        let error_with_kind =error.into_kind();
        match error_with_kind{
            _ => SecurityErrors::Unauthorized(format!("Error {:?}", error_with_kind))
        }
    }
}

impl From<std::io::Error> for SecurityErrors{
    fn from(value: std::io::Error) -> Self {
        match value {
            _ => SecurityErrors::GenericError(value.to_string())
        }
    }
}

impl From<SystemTimeError> for SecurityErrors{
    fn from(value: SystemTimeError) -> Self {
        match value {
            _SystemTimeError => {
                SecurityErrors::GenericError(String::from("Error while trying to get System Time"))
            }
        }
    }
}