
use poem::{middleware::Middleware, http::header::{CACHE_CONTROL, EXPIRES, PRAGMA},
http::HeaderValue, Endpoint, IntoResponse, Request, Response, Result};


#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct NoCacheMiddleware;


impl<E: Endpoint> Middleware<E> for NoCacheMiddleware {
    type Output = NoCacheEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        NoCacheEndpoint { ep }
    }
}

pub struct NoCacheEndpoint<E> {
    ep: E,
}

impl<E: Endpoint> Endpoint for NoCacheEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> Result<Self::Output> {
        let mut response = self.ep.call(req).await?.into_response();

        // setting Cache-Control, avoid cache store
        response.headers_mut().insert(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
        );

        // setting EXPIRES
        response
            .headers_mut()
            .insert(EXPIRES, HeaderValue::from_static("0"));

        // setting PRAGMA, compatible for HTTP/1.0
        response
            .headers_mut()
            .insert(PRAGMA, HeaderValue::from_static("no-cache"));

        Ok(response)
    }
}


#[cfg(test)]
mod tests {
    use poem::{endpoint::make_sync, http::header::{CACHE_CONTROL, EXPIRES, PRAGMA}, test::TestClient, EndpointExt as _};

    use crate::no_cache::NoCacheMiddleware;

    #[tokio::test]
    async fn test_rm_cache() {
        let ep = make_sync(|_| "hello").with(NoCacheMiddleware);
        let cli = TestClient::new(ep);
        let resp = cli.get("/").send().await;
        resp.assert_status_is_ok();
        resp.assert_header(CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0");
        resp.assert_header(EXPIRES, 0);
        resp.assert_header(PRAGMA, "no-cache")
    }   
}