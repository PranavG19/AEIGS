use axum::Router;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// A test HTTP server that binds to a random port on localhost and serves an
/// axum `Router` in a background tokio task. Automatically shuts down when
/// dropped.
pub struct TestServer {
    port: u16,
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Binds to `127.0.0.1:0` (OS-assigned port) and starts serving the
    /// given router in a background task.
    pub async fn new(router: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test server");
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        Self {
            port,
            handle: Some(handle),
        }
    }

    /// Returns the base URL of the running server, e.g. `http://127.0.0.1:12345`.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Returns the port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}
