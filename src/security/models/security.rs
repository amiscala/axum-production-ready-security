use core::fmt::{Display, Formatter};
use core::str::FromStr;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};

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
    pub sub: String,
    pub scopes: String,
    pub azp: String,
}
impl JwtClaims {
    pub fn new(
        aud: String,
        exp: usize,
        iat: usize,
        iss: String,
        nbf: usize,
        sub: String,
        scopes: String,
        azp: String,
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



