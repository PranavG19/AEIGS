use std::fmt;

#[derive(Debug)]
pub enum CrawlError {
    BrowserLaunch(String),
    Navigation(String),
    Timeout(String),
    Scope(String),
    Internal(String),
}

impl fmt::Display for CrawlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BrowserLaunch(msg) => write!(f, "browser launch failed: {msg}"),
            Self::Navigation(msg) => write!(f, "navigation error: {msg}"),
            Self::Timeout(msg) => write!(f, "timeout: {msg}"),
            Self::Scope(msg) => write!(f, "scope violation: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for CrawlError {}
