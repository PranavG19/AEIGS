mod crawler;
mod error;
pub mod injection_planter;
pub mod js_taint_analyzer;
mod page_fetcher;
mod types;
pub mod wasm_analyzer;
pub mod websocket_hijack;

#[cfg(feature = "browser")]
mod browser_fetcher;
#[cfg(feature = "browser")]
mod dom_verifier;

#[cfg(feature = "katana")]
pub mod katana_wrapper;

pub use crawler::Crawler;
pub use error::*;
pub use injection_planter::*;
pub use js_taint_analyzer::*;
pub use page_fetcher::*;
pub use types::*;
pub use wasm_analyzer::*;
pub use websocket_hijack::*;

#[cfg(feature = "browser")]
pub use browser_fetcher::*;
#[cfg(feature = "browser")]
pub use dom_verifier::*;

#[cfg(feature = "katana")]
pub use katana_wrapper::*;

#[cfg(test)]
#[path = "js_taint_analyzer_test.rs"]
mod js_taint_analyzer_test;

#[cfg(test)]
#[path = "page_fetcher_test.rs"]
mod page_fetcher_test;

#[cfg(test)]
#[path = "types_test.rs"]
mod types_test;

#[cfg(test)]
#[path = "wasm_analyzer_test.rs"]
mod wasm_analyzer_test;

#[cfg(all(test, feature = "katana"))]
#[path = "katana_wrapper_test.rs"]
mod katana_wrapper_test;
