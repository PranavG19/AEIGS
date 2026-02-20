use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PersonaId {
    ChromeDesktop,
    FirefoxDesktop,
    SafariDesktop,
    ChromeMobile,
    Googlebot,
    EdgeDesktop,
    OperaDesktop,
    SafariMobile,
    CurlClient,
    PythonRequests,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JitterDistribution {
    Uniform,
    Exponential,
    Normal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Persona {
    pub id: PersonaId,
    pub user_agent: String,
    pub accept_header: String,
    pub accept_language: String,
    pub accept_encoding: String,
    pub sec_fetch_headers: Vec<(String, String)>,
    pub header_order: Vec<String>,
    pub min_request_interval_ms: u64,
    pub max_request_interval_ms: u64,
    pub jitter_distribution: JitterDistribution,
}

impl Persona {
    pub fn custom(id: PersonaId) -> PersonaBuilder {
        PersonaBuilder {
            id,
            user_agent: String::new(),
            accept_header: String::new(),
            accept_language: "en-US,en;q=0.9".to_string(),
            accept_encoding: "gzip, deflate, br".to_string(),
            sec_fetch_headers: Vec::new(),
            header_order: Vec::new(),
            min_request_interval_ms: 500,
            max_request_interval_ms: 2000,
            jitter_distribution: JitterDistribution::Uniform,
        }
    }
}

pub struct PersonaBuilder {
    id: PersonaId,
    user_agent: String,
    accept_header: String,
    accept_language: String,
    accept_encoding: String,
    sec_fetch_headers: Vec<(String, String)>,
    header_order: Vec<String>,
    min_request_interval_ms: u64,
    max_request_interval_ms: u64,
    jitter_distribution: JitterDistribution,
}

impl PersonaBuilder {
    pub fn with_user_agent(mut self, ua: &str) -> Self {
        self.user_agent = ua.to_string();
        self
    }

    pub fn with_accept_header(mut self, accept: &str) -> Self {
        self.accept_header = accept.to_string();
        self
    }

    pub fn with_accept_language(mut self, lang: &str) -> Self {
        self.accept_language = lang.to_string();
        self
    }

    pub fn with_accept_encoding(mut self, encoding: &str) -> Self {
        self.accept_encoding = encoding.to_string();
        self
    }

    pub fn with_sec_fetch_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.sec_fetch_headers = headers;
        self
    }

    pub fn with_header_order(mut self, order: Vec<String>) -> Self {
        self.header_order = order;
        self
    }

    pub fn with_request_interval(mut self, min_ms: u64, max_ms: u64) -> Self {
        self.min_request_interval_ms = min_ms;
        self.max_request_interval_ms = max_ms;
        self
    }

    pub fn with_jitter_distribution(mut self, dist: JitterDistribution) -> Self {
        self.jitter_distribution = dist;
        self
    }

    pub fn build(self) -> Persona {
        Persona {
            id: self.id,
            user_agent: self.user_agent,
            accept_header: self.accept_header,
            accept_language: self.accept_language,
            accept_encoding: self.accept_encoding,
            sec_fetch_headers: self.sec_fetch_headers,
            header_order: self.header_order,
            min_request_interval_ms: self.min_request_interval_ms,
            max_request_interval_ms: self.max_request_interval_ms,
            jitter_distribution: self.jitter_distribution,
        }
    }
}

#[derive(Debug)]
pub enum CatalogError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    EmptyCatalog,
    DuplicateId(PersonaId),
    EmptyUserAgent(PersonaId),
    EmptyAcceptHeader(PersonaId),
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "failed to read persona catalog: {e}"),
            Self::Parse(e) => write!(f, "failed to parse persona catalog: {e}"),
            Self::EmptyCatalog => write!(f, "persona catalog must contain at least one persona"),
            Self::DuplicateId(id) => write!(f, "duplicate persona id in catalog: {id:?}"),
            Self::EmptyUserAgent(id) => {
                write!(f, "persona {id:?} has empty user_agent")
            }
            Self::EmptyAcceptHeader(id) => {
                write!(f, "persona {id:?} has empty accept_header")
            }
        }
    }
}

impl std::error::Error for CatalogError {}

const DEFAULT_CATALOG_JSON: &str = include_str!("../data/default_personas.json");

/// Loads the persona catalog from an optional file path.
///
/// When `path` is `Some`, reads and parses the file at that path.
/// When `path` is `None`, uses the embedded default catalog compiled into the binary.
/// In both cases, the loaded catalog is validated for non-emptiness, unique IDs,
/// and non-empty required fields.
pub fn load_persona_catalog(path: Option<&Path>) -> Result<Vec<Persona>, CatalogError> {
    let json = match path {
        Some(p) => std::fs::read_to_string(p).map_err(CatalogError::Io)?,
        None => DEFAULT_CATALOG_JSON.to_string(),
    };
    let personas: Vec<Persona> = serde_json::from_str(&json).map_err(CatalogError::Parse)?;
    validate_catalog(&personas)?;
    Ok(personas)
}

fn validate_catalog(personas: &[Persona]) -> Result<(), CatalogError> {
    if personas.is_empty() {
        return Err(CatalogError::EmptyCatalog);
    }
    let mut seen_ids = HashSet::with_capacity(personas.len());
    for persona in personas {
        if !seen_ids.insert(persona.id) {
            return Err(CatalogError::DuplicateId(persona.id));
        }
        if persona.user_agent.is_empty() {
            return Err(CatalogError::EmptyUserAgent(persona.id));
        }
        if persona.accept_header.is_empty() {
            return Err(CatalogError::EmptyAcceptHeader(persona.id));
        }
    }
    Ok(())
}

/// Returns the default embedded persona catalog.
///
/// Panics if the embedded JSON is invalid, which would indicate a build-time data corruption.
pub fn persona_catalog() -> Vec<Persona> {
    load_persona_catalog(None).expect("embedded default persona catalog is valid")
}

#[cfg(test)]
#[path = "persona_test.rs"]
mod persona_test;
