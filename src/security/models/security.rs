use core::fmt::{Display, Formatter};
use core::str::FromStr;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub struct JwtConfig {
    pub private_key: EncodingKey,
    pub public_key: DecodingKey,
    pub token_expiration_in_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtClaims {
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub nbf: usize,
    pub sub: Uuid,
    pub scopes: String,
    pub azp: Uuid,
}
impl JwtClaims {
    pub fn new(
        aud: String,
        exp: usize,
        iat: usize,
        iss: String,
        nbf: usize,
        sub: Uuid,
        scopes: String,
        azp: Uuid,
    ) -> Self {
        Self {
            aud,
            exp,
            iat,
            iss,
            nbf,
            sub,
            scopes,
            azp,
        }
    }
}



