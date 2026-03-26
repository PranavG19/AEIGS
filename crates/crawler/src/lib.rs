pub mod auth_automator;
pub mod browser_ext_analyzer;
mod crawler;
mod error;
pub mod form_autofill;
pub mod gpu_browser;
pub mod headless_controller;
pub mod injection_planter;
pub mod js_engine;
pub mod js_executor;
pub mod js_taint_analyzer;
pub mod multi_bot_coordinator;
mod page_fetcher;
pub mod postmessage_attack;
pub mod spa_crawler;
mod types;
pub mod visual_regression;
pub mod wasm_analyzer;
pub mod websocket_hijack;

#[cfg(feature = "browser")]
mod browser_fetcher;
#[cfg(feature = "browser")]
mod dom_verifier;

#[cfg(feature = "katana")]
pub mod katana_wrapper;

pub use auth_automator::*;
pub use browser_ext_analyzer::*;
pub use crawler::Crawler;
pub use error::*;
pub use form_autofill::*;
pub use gpu_browser::*;
pub use headless_controller::*;
pub use injection_planter::*;
pub use js_engine::*;
pub use js_executor::*;
pub use js_taint_analyzer::*;
pub use multi_bot_coordinator::*;
pub use page_fetcher::*;
pub use postmessage_attack::*;
pub use spa_crawler::*;
pub use types::*;
pub use visual_regression::*;
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

#[cfg(test)]
#[path = "auth_automator_test.rs"]
mod auth_automator_test;

#[cfg(test)]
#[path = "browser_ext_analyzer_test.rs"]
mod browser_ext_analyzer_test;

#[cfg(test)]
#[path = "form_autofill_test.rs"]
mod form_autofill_test;

#[cfg(test)]
#[path = "headless_controller_test.rs"]
mod headless_controller_test;

#[cfg(test)]
#[path = "injection_planter_test.rs"]
mod injection_planter_test;

#[cfg(test)]
#[path = "js_executor_test.rs"]
mod js_executor_test;

#[cfg(test)]
#[path = "multi_bot_coordinator_test.rs"]
mod multi_bot_coordinator_test;

#[cfg(test)]
#[path = "postmessage_attack_test.rs"]
mod postmessage_attack_test;

#[cfg(test)]
#[path = "spa_crawler_test.rs"]
mod spa_crawler_test;

#[cfg(test)]
#[path = "visual_regression_test.rs"]
mod visual_regression_test;

#[cfg(test)]
#[path = "websocket_hijack_test.rs"]
mod websocket_hijack_test;

#[cfg(test)]
#[path = "gpu_browser_test.rs"]
mod gpu_browser_test;

#[cfg(test)]
#[path = "js_engine_test.rs"]
mod js_engine_test;
