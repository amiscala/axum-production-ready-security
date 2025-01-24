use opentelemetry::{Key, KeyValue, Value};
use axum_extra::headers;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use axum::Extension;
use axum::middleware::Next;
use axum::extract::Request;
use axum::http::header;
use axum_extra::headers::{Authorization, HeaderMapExt};
use axum_extra::headers::authorization::Bearer;
use axum_extra::TypedHeader;
use jsonwebtoken::decode;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use crate::security::models::{JwtClaims, JwtConfig};
use opentelemetry::trace::TraceContextExt;
use crate::{validate_jwt_token, SecurityErrors};

pub async fn authentication_middleware<T: IntoResponse+From<SecurityErrors>>
(
    jwt_config: Extension<Arc<JwtConfig>>,
    mut request: Request,
    next: Next,
) -> Response {
    let auth_header = request.headers().typed_get::<Authorization<Bearer>>();
    match auth_header {
        Some(auth_header) => {
            let token = auth_header.token();
            let claims = validate_jwt_token(&jwt_config, token);
            match claims {
                Ok(claims) => {
                    let current_context = tracing::Span::current().context();
                    let span = current_context.span();
                    let user_id = KeyValue::new(Key::from_static_str("user_id"), Value::from(claims.sub.to_owned()));
                    span.set_attribute(user_id);
                    let client_id = KeyValue::new(Key::from_static_str("client_id"),Value::from(claims.azp.to_owned()));
                    span.set_attribute(client_id);
                    let arc_claims = Arc::new(claims);
                    request.extensions_mut().insert(arc_claims);
                    next.run(request).await

                }
                Err(err) => {
                    T::from(err).into_response()
                }
            }
        }
        None => {
            T::from(SecurityErrors::MissingAuthorizationHeader("Missing Authorization header".to_string())).into_response()
        }
    }
}

