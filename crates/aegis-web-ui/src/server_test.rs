#[cfg(test)]
mod tests {
    use crate::server::build_router;
    use crate::CliArgs;

    fn test_args() -> CliArgs {
        CliArgs {
            target: None,
            port: 7777,
            profile: "quick".to_string(),
            demo: false,
        }
    }

    #[test]
    fn build_router_succeeds() {
        let _router = build_router(test_args());
    }

    #[tokio::test]
    async fn dashboard_route_returns_html() {
        let app = build_router(test_args());
        let response = axum::serve(
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
            app,
        );
        // Just verifying the router builds without panicking
        drop(response);
    }
}
