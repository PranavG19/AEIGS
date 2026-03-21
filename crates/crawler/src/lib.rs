mod crawler;
mod error;
mod page_fetcher;
mod types;

#[cfg(feature = "browser")]
mod browser_fetcher;
#[cfg(feature = "browser")]
mod dom_verifier;

#[cfg(feature = "katana")]
pub mod katana_wrapper;

pub use crawler::Crawler;
pub use error::*;
pub use page_fetcher::*;
pub use types::*;

#[cfg(feature = "browser")]
pub use browser_fetcher::*;
#[cfg(feature = "browser")]
pub use dom_verifier::*;

#[cfg(feature = "katana")]
pub use katana_wrapper::*;

#[cfg(all(test, feature = "katana"))]
#[path = "katana_wrapper_test.rs"]
mod katana_wrapper_test;
