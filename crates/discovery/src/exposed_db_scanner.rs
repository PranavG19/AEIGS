/// Scanner for internet-facing databases without authentication.
///
/// Detects open MongoDB, Redis, Elasticsearch, CouchDB, Cassandra,
/// Memcached, and PostgreSQL instances. For each database type the
/// scanner produces a connection string, data-sampling commands, and
/// a severity score reflecting the exposure risk.
/// Default ports for each supported database engine.
pub const MONGODB_DEFAULT_PORT: u16 = 27017;
pub const REDIS_DEFAULT_PORT: u16 = 6379;
pub const ELASTICSEARCH_DEFAULT_PORT: u16 = 9200;
pub const COUCHDB_DEFAULT_PORT: u16 = 5984;
pub const CASSANDRA_DEFAULT_PORT: u16 = 9042;
pub const MEMCACHED_DEFAULT_PORT: u16 = 11211;
pub const POSTGRES_DEFAULT_PORT: u16 = 5432;

/// Supported database engine types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatabaseEngine {
    MongoDB,
    Redis,
    Elasticsearch,
    CouchDB,
    Cassandra,
    Memcached,
    PostgreSQL,
}

impl std::fmt::Display for DatabaseEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MongoDB => write!(f, "MongoDB"),
            Self::Redis => write!(f, "Redis"),
            Self::Elasticsearch => write!(f, "Elasticsearch"),
            Self::CouchDB => write!(f, "CouchDB"),
            Self::Cassandra => write!(f, "Cassandra"),
            Self::Memcached => write!(f, "Memcached"),
            Self::PostgreSQL => write!(f, "PostgreSQL"),
        }
    }
}

impl DatabaseEngine {
    /// All supported engine variants.
    pub fn all() -> &'static [DatabaseEngine] {
        &[
            Self::MongoDB,
            Self::Redis,
            Self::Elasticsearch,
            Self::CouchDB,
            Self::Cassandra,
            Self::Memcached,
            Self::PostgreSQL,
        ]
    }

    /// Well-known default port for this engine.
    pub fn default_port(&self) -> u16 {
        match self {
            Self::MongoDB => MONGODB_DEFAULT_PORT,
            Self::Redis => REDIS_DEFAULT_PORT,
            Self::Elasticsearch => ELASTICSEARCH_DEFAULT_PORT,
            Self::CouchDB => COUCHDB_DEFAULT_PORT,
            Self::Cassandra => CASSANDRA_DEFAULT_PORT,
            Self::Memcached => MEMCACHED_DEFAULT_PORT,
            Self::PostgreSQL => POSTGRES_DEFAULT_PORT,
        }
    }
}

/// How severe an exposed database finding is, from informational to critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExposedDbSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl ExposedDbSeverity {
    /// Numeric score in \[0.0, 1.0\] for sorting and aggregation.
    pub fn score(&self) -> f64 {
        match self {
            Self::Informational => 0.1,
            Self::Low => 0.3,
            Self::Medium => 0.5,
            Self::High => 0.8,
            Self::Critical => 1.0,
        }
    }
}

/// A single default-credential pair to try against a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultCredential {
    pub username: String,
    pub password: String,
}

/// Probe specification for a single database engine on a given host.
#[derive(Debug, Clone, PartialEq)]
pub struct DatabaseProbe {
    pub engine: DatabaseEngine,
    pub host: String,
    pub port: u16,
    pub connection_string: String,
    pub sampling_commands: Vec<String>,
    pub default_credentials: Vec<DefaultCredential>,
}

/// Result of probing a single database instance.
#[derive(Debug, Clone, PartialEq)]
pub struct ExposedDbFinding {
    pub engine: DatabaseEngine,
    pub host: String,
    pub port: u16,
    pub connection_string: String,
    pub sampling_commands: Vec<String>,
    pub severity: ExposedDbSeverity,
    pub detail: String,
}

/// Error type for the exposed-database scanner.
#[derive(Debug)]
pub enum ExposedDbScanError {
    InvalidHost(String),
    ConnectionFailed(String),
    Timeout(String),
}

impl std::fmt::Display for ExposedDbScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHost(h) => write!(f, "invalid host: {h}"),
            Self::ConnectionFailed(m) => write!(f, "connection failed: {m}"),
            Self::Timeout(m) => write!(f, "timeout: {m}"),
        }
    }
}

/// Generate a connection string for the given engine, host, port, and
/// optional credentials.
pub fn connection_string(
    engine: DatabaseEngine,
    host: &str,
    port: u16,
    creds: Option<&DefaultCredential>,
) -> String {
    match engine {
        DatabaseEngine::MongoDB => {
            if let Some(c) = creds {
                format!(
                    "mongodb://{}:{}@{}:{}/admin",
                    c.username, c.password, host, port
                )
            } else {
                format!("mongodb://{}:{}/admin", host, port)
            }
        }
        DatabaseEngine::Redis => {
            if let Some(c) = creds {
                format!("redis://:{}@{}:{}/0", c.password, host, port)
            } else {
                format!("redis://{}:{}/0", host, port)
            }
        }
        DatabaseEngine::Elasticsearch => {
            if let Some(c) = creds {
                format!("http://{}:{}@{}:{}", c.username, c.password, host, port)
            } else {
                format!("http://{}:{}", host, port)
            }
        }
        DatabaseEngine::CouchDB => {
            if let Some(c) = creds {
                format!(
                    "http://{}:{}@{}:{}/_all_dbs",
                    c.username, c.password, host, port
                )
            } else {
                format!("http://{}:{}/_all_dbs", host, port)
            }
        }
        DatabaseEngine::Cassandra => {
            if let Some(c) = creds {
                format!(
                    "cassandra://{}:{}@{}:{}",
                    c.username, c.password, host, port
                )
            } else {
                format!("cassandra://{}:{}", host, port)
            }
        }
        DatabaseEngine::Memcached => {
            format!("memcached://{}:{}", host, port)
        }
        DatabaseEngine::PostgreSQL => {
            if let Some(c) = creds {
                format!(
                    "postgresql://{}:{}@{}:{}/postgres",
                    c.username, c.password, host, port
                )
            } else {
                format!("postgresql://{}:{}/postgres", host, port)
            }
        }
    }
}

/// Return the default credentials commonly shipped with each engine.
pub fn default_credentials(engine: DatabaseEngine) -> Vec<DefaultCredential> {
    match engine {
        DatabaseEngine::MongoDB => vec![
            DefaultCredential {
                username: "admin".into(),
                password: "admin".into(),
            },
            DefaultCredential {
                username: "root".into(),
                password: "root".into(),
            },
            DefaultCredential {
                username: "admin".into(),
                password: "".into(),
            },
            DefaultCredential {
                username: "mongouser".into(),
                password: "mongopass".into(),
            },
        ],
        DatabaseEngine::Redis => vec![
            DefaultCredential {
                username: "".into(),
                password: "".into(),
            },
            DefaultCredential {
                username: "".into(),
                password: "redis".into(),
            },
            DefaultCredential {
                username: "default".into(),
                password: "redis".into(),
            },
        ],
        DatabaseEngine::Elasticsearch => vec![
            DefaultCredential {
                username: "elastic".into(),
                password: "changeme".into(),
            },
            DefaultCredential {
                username: "elastic".into(),
                password: "elastic".into(),
            },
        ],
        DatabaseEngine::CouchDB => vec![
            DefaultCredential {
                username: "admin".into(),
                password: "admin".into(),
            },
            DefaultCredential {
                username: "couchdb".into(),
                password: "couchdb".into(),
            },
        ],
        DatabaseEngine::Cassandra => vec![DefaultCredential {
            username: "cassandra".into(),
            password: "cassandra".into(),
        }],
        DatabaseEngine::Memcached => vec![],
        DatabaseEngine::PostgreSQL => vec![
            DefaultCredential {
                username: "postgres".into(),
                password: "postgres".into(),
            },
            DefaultCredential {
                username: "postgres".into(),
                password: "".into(),
            },
            DefaultCredential {
                username: "admin".into(),
                password: "admin".into(),
            },
        ],
    }
}

/// Produce the sampling / enumeration commands you would run once
/// connected to the given engine.
pub fn sampling_commands(engine: DatabaseEngine) -> Vec<String> {
    match engine {
        DatabaseEngine::MongoDB => vec![
            "show dbs".into(),
            "db.getCollectionNames()".into(),
            "db.stats()".into(),
            "db.serverStatus().connections".into(),
            "db.adminCommand('listDatabases')".into(),
        ],
        DatabaseEngine::Redis => vec![
            "INFO server".into(),
            "INFO keyspace".into(),
            "CONFIG GET *".into(),
            "DBSIZE".into(),
            "KEYS * (LIMIT 100)".into(),
            "CLIENT LIST".into(),
        ],
        DatabaseEngine::Elasticsearch => vec![
            "GET /_cat/indices?v".into(),
            "GET /_cluster/health".into(),
            "GET /_cluster/stats".into(),
            "GET /_nodes/stats".into(),
            "GET /_cat/nodes?v".into(),
            "GET /_search?size=1".into(),
        ],
        DatabaseEngine::CouchDB => vec![
            "GET /_all_dbs".into(),
            "GET /_active_tasks".into(),
            "GET /_node/_local/_config".into(),
            "GET /_utils".into(),
            "GET /_membership".into(),
        ],
        DatabaseEngine::Cassandra => vec![
            "DESCRIBE KEYSPACES".into(),
            "SELECT * FROM system_schema.keyspaces".into(),
            "SELECT * FROM system.local".into(),
            "SELECT peer FROM system.peers".into(),
            "DESCRIBE TABLES".into(),
        ],
        DatabaseEngine::Memcached => vec![
            "stats".into(),
            "stats items".into(),
            "stats slabs".into(),
            "stats cachedump 1 100".into(),
            "version".into(),
        ],
        DatabaseEngine::PostgreSQL => vec![
            "SELECT datname FROM pg_database".into(),
            "SELECT tablename FROM pg_tables WHERE schemaname='public'".into(),
            "SELECT version()".into(),
            "SELECT current_user".into(),
            "\\du".into(),
            "SELECT * FROM pg_stat_activity".into(),
        ],
    }
}

/// Assign severity based on the database engine. Databases that store
/// persistent, queryable data with no auth are Critical; caches and
/// search indices are High.
pub fn severity_for_engine(engine: DatabaseEngine) -> ExposedDbSeverity {
    match engine {
        DatabaseEngine::MongoDB => ExposedDbSeverity::Critical,
        DatabaseEngine::PostgreSQL => ExposedDbSeverity::Critical,
        DatabaseEngine::CouchDB => ExposedDbSeverity::Critical,
        DatabaseEngine::Cassandra => ExposedDbSeverity::Critical,
        DatabaseEngine::Elasticsearch => ExposedDbSeverity::High,
        DatabaseEngine::Redis => ExposedDbSeverity::High,
        DatabaseEngine::Memcached => ExposedDbSeverity::Medium,
    }
}

/// Build a full `DatabaseProbe` for a specific engine against the given host.
/// Uses the engine's default port unless overridden.
pub fn build_probe(
    engine: DatabaseEngine,
    host: &str,
    port_override: Option<u16>,
) -> DatabaseProbe {
    let port = port_override.unwrap_or_else(|| engine.default_port());
    let creds = default_credentials(engine);
    let conn = connection_string(engine, host, port, None);
    let cmds = sampling_commands(engine);
    DatabaseProbe {
        engine,
        host: host.to_string(),
        port,
        connection_string: conn,
        sampling_commands: cmds,
        default_credentials: creds,
    }
}

/// Build probes for every supported engine against a single host.
pub fn build_all_probes(host: &str) -> Vec<DatabaseProbe> {
    DatabaseEngine::all()
        .iter()
        .map(|e| build_probe(*e, host, None))
        .collect()
}

/// Simulated scan result: build an `ExposedDbFinding` for a confirmed
/// open instance.
pub fn finding_from_probe(probe: &DatabaseProbe) -> ExposedDbFinding {
    let severity = severity_for_engine(probe.engine);
    ExposedDbFinding {
        engine: probe.engine,
        host: probe.host.clone(),
        port: probe.port,
        connection_string: probe.connection_string.clone(),
        sampling_commands: probe.sampling_commands.clone(),
        severity,
        detail: format!(
            "{} instance at {}:{} appears open with no authentication",
            probe.engine, probe.host, probe.port
        ),
    }
}

/// The main scanner entry-point. Builds probes for every engine on the
/// given host and returns them paired with the severity score.
pub struct ExposedDbScanner {
    pub host: String,
    pub port_overrides: std::collections::HashMap<DatabaseEngine, u16>,
}

impl ExposedDbScanner {
    pub fn new(host: &str) -> Self {
        Self {
            host: host.to_string(),
            port_overrides: std::collections::HashMap::new(),
        }
    }

    pub fn with_port(mut self, engine: DatabaseEngine, port: u16) -> Self {
        self.port_overrides.insert(engine, port);
        self
    }

    /// Generate probes for all engines, respecting port overrides.
    pub fn probes(&self) -> Vec<DatabaseProbe> {
        DatabaseEngine::all()
            .iter()
            .map(|e| {
                let port = self.port_overrides.get(e).copied();
                build_probe(*e, &self.host, port)
            })
            .collect()
    }

    /// Generate probes for a specific subset of engines.
    pub fn probes_for(&self, engines: &[DatabaseEngine]) -> Vec<DatabaseProbe> {
        engines
            .iter()
            .map(|e| {
                let port = self.port_overrides.get(e).copied();
                build_probe(*e, &self.host, port)
            })
            .collect()
    }
}
