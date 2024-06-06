use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use poem::{middleware::Middleware, Endpoint, IntoResponse, Request, Response, Result};

use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct SignVerifyMiddleware {
    secret_key: String,
    allowed_time_window: i64,
}

impl SignVerifyMiddleware {
    #[must_use]
    pub fn new(secret: &str, allowed_time: i64) -> SignVerifyMiddleware {
        Self {
            secret_key: secret.to_string(),
            allowed_time_window: allowed_time,
        }
    }
}

impl<E: Endpoint> Middleware<E> for SignVerifyMiddleware {
    type Output = SignVerifyEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        SignVerifyEndpoint {
            ep,
            secret_key: self.secret_key.clone(),
            allowed_time_window: self.allowed_time_window,
        }
    }
}

#[allow(clippy::type_complexity)]
pub struct SignVerifyEndpoint<E> {
    ep: E,
    secret_key: String,
    allowed_time_window: i64,
}

impl<E: Endpoint> Endpoint for SignVerifyEndpoint<E> {
    type Output = Response;

    async fn call(&self, mut req: Request) -> Result<Self::Output> {
        let sign = req
            .header("apiSig")
            .ok_or_else(|| {
                poem::Error::from_string(
                    "missing header apiSig",
                    poem::http::StatusCode::BAD_REQUEST,
                )
            })?
            .to_string();

        let timestamp = req
            .header("timestamp")
            .ok_or_else(|| {
                poem::Error::from_string(
                    "missing header timestamp",
                    poem::http::StatusCode::BAD_REQUEST,
                )
            })?
            .parse::<i64>()
            .map_err(|_| {
                poem::Error::from_string(
                    "timestamp parse error",
                    poem::http::StatusCode::BAD_REQUEST,
                )
            })?;
        let now = Utc::now().naive_utc().and_utc().timestamp();
        if (timestamp - now).abs() > self.allowed_time_window {
            return Err(poem::Error::from_string(
                "request timeout",
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }

        let uri = req.uri().clone();

        let method = req.method().clone();
        let mut mac = HmacSha256::new_from_slice(self.secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        let mut string_to_sign = String::new();
        string_to_sign.push_str(&uri.to_string().split('?').last().unwrap());

        let body = req.take_body().into_bytes().await?;
        let body_str = String::from_utf8(body.to_vec())
            .map_err(|_| {
                poem::Error::from_string("body parse error", poem::http::StatusCode::BAD_REQUEST)
            })?
            .clone();

        if method != poem::http::Method::GET {
            string_to_sign.push_str(&body_str);
        }

        mac.update(string_to_sign.as_bytes());

        let sign_decode = general_purpose::STANDARD
            .decode(sign.as_bytes())
            .map_err(|_| {
                poem::Error::from_string(
                    "base64 decode signature error",
                    poem::http::StatusCode::BAD_REQUEST,
                )
            })
            .unwrap();
        let flag = mac.verify_slice(&sign_decode[..]).is_ok();
        if !flag {
            return Err(poem::Error::from_string(
                "api signature verify error",
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }
        req.set_body(body);

        let response = self.ep.call(req).await?.into_response();
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use crate::param_verify::{HmacSha256, SignVerifyMiddleware};
    use base64::{engine::general_purpose, Engine};
    use chrono::Utc;
    use hmac::{Hmac, Mac};
    use poem::{endpoint::make_sync, test::TestClient, EndpointExt};

    const SECRET_KEY: &[u8] = b"your_secret_key";

    #[test]
    fn test_encode() {
        let mut mac =
            HmacSha256::new_from_slice(SECRET_KEY).expect("HMAC can take key of any size");
        mac.update(b"address=init&linkType=0");
        let result = general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert_eq!("kEU67gzX2pYgGlhsHXDxg0YtM7z8YYG6cQI8rl22eF4=", result);
    }

    #[test]
    fn test_decode() {
        let input = "OWvqzTbt3GhtPZUIQs9Z8g6KS/FroM7a4EUVWocFWP4=".to_string();
        let decode_bytes = general_purpose::STANDARD.decode(input.as_bytes()).unwrap();
        let mut mac =
            HmacSha256::new_from_slice(b"your_secret_key").expect("HMAC can take key of any size");
        mac.update(b"/api/available-code?address=init&linkType=0");
        let result = mac.verify_slice(&decode_bytes[..]).is_ok();
        assert_eq!(true, result)
    }

    #[tokio::test]
    async fn test_check() {
        let ep = make_sync(|_| "hello").with(SignVerifyMiddleware::new("your_secret_key", 20));
        let cli = TestClient::new(ep);

        let now = Utc::now().naive_utc().and_utc().timestamp();
        let resp = cli
            .get("/api/available-code")
            .query("address", &"init")
            .query("linkType", &0)
            .header("apiSig", "kEU67gzX2pYgGlhsHXDxg0YtM7z8YYG6cQI8rl22eF4=")
            .header("timestamp", now)
            .send()
            .await;

        resp.assert_status_is_ok();
    }
}
