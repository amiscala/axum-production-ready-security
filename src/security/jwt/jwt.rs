use crate::security::models::security::{JwtClaims};
use std::time::Duration;
use crate::security::models::JwtConfig;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::fs;
use std::ops::Add;
use std::time::SystemTime;
use uuid::Uuid;
use crate::SecurityErrors;

const JWT_AUDIENCE: &str = env!("CARGO_PKG_NAME");
const JWT_ISSUER: &str = env!("CARGO_PKG_NAME");
const JWT_ALG: Algorithm = Algorithm::RS512;

pub fn get_jwt_configuration(
    private_key_file_path: &str,
    public_key_file_path: &str,
    token_expiration_in_seconds: u64,
) -> Result<JwtConfig, SecurityErrors> {
    let private_key_bytes = fs::read(private_key_file_path)?;
    let private_key = EncodingKey::from_rsa_pem(&private_key_bytes)?;
    let public_key_bytes = fs::read(public_key_file_path)?;
    let public_key = DecodingKey::from_rsa_pem(&public_key_bytes)?;
    Ok(JwtConfig {
        private_key,
        public_key,
        token_expiration_in_seconds,
    })
}

pub fn issue_jwt_token(jwt_config: &JwtConfig, client_id: Uuid, user_id:Uuid, scopes: String ) -> Result<String, SecurityErrors> {
    let now = SystemTime::now();
    let iat = now
        .clone()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as usize;
    let exp = now
        .add(Duration::from_secs(jwt_config.token_expiration_in_seconds))
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as usize;
    let nbf = iat.clone();
    let claims = JwtClaims::new(
        JWT_AUDIENCE.to_string(),
        exp,
        iat,
        JWT_ISSUER.to_string(),
        nbf,
        user_id,
        scopes,
        client_id
    );
    let token_header = Header::new(JWT_ALG);
    let token = encode(&token_header, &claims, &jwt_config.private_key)?;
    Ok(token.to_string())
}

pub fn validate_jwt_token(jwt_config: &JwtConfig, token: &str) -> Result<JwtClaims, SecurityErrors> {
    let validations = get_validation_parameters();
    let token_data = decode::<JwtClaims>(token, &jwt_config.public_key, &validations)?;
    Ok(token_data.claims)
}

fn get_validation_parameters() -> Validation {
    let mut validation = Validation::new(JWT_ALG);
    validation.set_required_spec_claims(&["aud", "iss"]);
    validation.set_audience(&[JWT_AUDIENCE]);
    validation.set_issuer(&[JWT_ISSUER]);
    validation
}
