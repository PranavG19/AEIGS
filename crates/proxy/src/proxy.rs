use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::persistence::ProxyDb;
use crate::types::{ProxyConfig, RecordedExchange};

/// Handle returned from `start_proxy`, used to query logs and shut down.
pub struct ProxyHandle {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    log: Arc<RwLock<Vec<RecordedExchange>>>,
    listen_addr: SocketAddr,
    db: Option<Arc<std::sync::Mutex<ProxyDb>>>,
}

impl ProxyHandle {
    pub async fn exchanges(&self) -> Vec<RecordedExchange> {
        self.log.read().await.clone()
    }

    pub async fn exchange_count(&self) -> usize {
        self.log.read().await.len()
    }

    pub async fn exchange_by_id(&self, id: u64) -> Option<RecordedExchange> {
        self.log.read().await.iter().find(|e| e.id == id).cloned()
    }

    pub async fn clear_log(&self) {
        self.log.write().await.clear();
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Returns the optional persistence database, if configured.
    pub fn db(&self) -> Option<&Arc<std::sync::Mutex<ProxyDb>>> {
        self.db.as_ref()
    }

    /// Shut down the proxy server gracefully.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Start the recording proxy, returning a handle for control and querying.
pub async fn start_proxy(config: ProxyConfig) -> Result<ProxyHandle, std::io::Error> {
    let listener = TcpListener::bind(config.listen_addr).await?;
    let listen_addr = listener.local_addr()?;
    let log: Arc<RwLock<Vec<RecordedExchange>>> = Arc::new(RwLock::new(Vec::new()));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let counter = Arc::new(AtomicU64::new(1));
    let max_log_size = config.max_log_size;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build reqwest client");

    let db = config.db_path.as_ref().map(|path| {
        let proxy_db = ProxyDb::open(path).expect("failed to open proxy database");
        Arc::new(std::sync::Mutex::new(proxy_db))
    });

    let log_clone = Arc::clone(&log);
    let db_clone = db.clone();
    tokio::spawn(accept_loop(
        listener,
        shutdown_rx,
        log_clone,
        counter,
        max_log_size,
        client,
        db_clone,
    ));

    Ok(ProxyHandle {
        shutdown_tx: Some(shutdown_tx),
        log,
        listen_addr,
        db,
    })
}

async fn accept_loop(
    listener: TcpListener,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    log: Arc<RwLock<Vec<RecordedExchange>>>,
    counter: Arc<AtomicU64>,
    max_log_size: usize,
    client: reqwest::Client,
    db: Option<Arc<std::sync::Mutex<ProxyDb>>>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accept_result = listener.accept() => {
                let Ok((stream, _addr)) = accept_result else {
                    continue;
                };
                let log = Arc::clone(&log);
                let counter = Arc::clone(&counter);
                let client = client.clone();
                let db = db.clone();
                let io = hyper_util::rt::TokioIo::new(stream);
                tokio::spawn(async move {
                    let svc = service_fn(|req| {
                        handle_request(
                            req,
                            Arc::clone(&log),
                            Arc::clone(&counter),
                            max_log_size,
                            client.clone(),
                            db.clone(),
                        )
                    });
                    let _ = http1::Builder::new()
                        .preserve_header_case(true)
                        .serve_connection(io, svc)
                        .await;
                });
            }
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    log: Arc<RwLock<Vec<RecordedExchange>>>,
    counter: Arc<AtomicU64>,
    max_log_size: usize,
    client: reqwest::Client,
    db: Option<Arc<std::sync::Mutex<ProxyDb>>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start = SystemTime::now();
    let timestamp_ms = start
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let method = req.method().clone();
    let uri = req.uri().to_string();
    let req_headers = extract_headers(req.headers());

    let req_body_bytes = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();

    let forward_result =
        forward_request(&client, &method, &uri, &req_headers, &req_body_bytes).await;

    let elapsed = start.elapsed().unwrap_or_default().as_millis() as u64;

    let (status, resp_headers, resp_body) = match forward_result {
        Ok(parts) => parts,
        Err(_) => (502, vec![], b"Bad Gateway".to_vec()),
    };

    let exchange = RecordedExchange {
        id: counter.fetch_add(1, Ordering::Relaxed),
        request_method: method.to_string(),
        request_url: uri,
        request_headers: req_headers,
        request_body: req_body_bytes,
        response_status: status,
        response_headers: resp_headers.clone(),
        response_body: resp_body.clone(),
        timestamp_ms,
        duration_ms: elapsed,
        in_scope: true,
        tags: vec![],
    };

    append_exchange(&log, exchange, max_log_size, &db).await;

    let mut builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    Ok(builder
        .body(Full::new(Bytes::from(resp_body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Internal Error")))))
}

fn extract_headers(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect()
}

async fn forward_request(
    client: &reqwest::Client,
    method: &hyper::Method,
    uri: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), reqwest::Error> {
    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);

    let mut req_builder = client.request(reqwest_method, uri);
    for (name, value) in headers {
        if is_hop_by_hop_header(name) {
            continue;
        }
        req_builder = req_builder.header(name.as_str(), value.as_str());
    }
    if !body.is_empty() {
        req_builder = req_builder.body(body.to_vec());
    }

    let resp = req_builder.send().await?;
    let status = resp.status().as_u16();
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let resp_body = resp.bytes().await?.to_vec();
    Ok((status, resp_headers, resp_body))
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

async fn append_exchange(
    log: &RwLock<Vec<RecordedExchange>>,
    exchange: RecordedExchange,
    max_log_size: usize,
    db: &Option<Arc<std::sync::Mutex<ProxyDb>>>,
) {
    if let Some(db) = db
        && let Ok(guard) = db.lock()
    {
        let _ = guard.insert_exchange(&exchange);
    }
    let mut entries = log.write().await;
    if entries.len() >= max_log_size {
        entries.remove(0);
    }
    entries.push(exchange);
}

#[cfg(test)]
#[path = "proxy_test.rs"]
mod proxy_test;
