use crate::exposed_db_scanner::{
    build_all_probes, build_probe, connection_string, default_credentials, finding_from_probe,
    sampling_commands, severity_for_engine, DatabaseEngine, DefaultCredential, ExposedDbScanner,
    ExposedDbSeverity, CASSANDRA_DEFAULT_PORT, COUCHDB_DEFAULT_PORT, ELASTICSEARCH_DEFAULT_PORT,
    MEMCACHED_DEFAULT_PORT, MONGODB_DEFAULT_PORT, POSTGRES_DEFAULT_PORT, REDIS_DEFAULT_PORT,
};

#[test]
fn all_engines_listed() {
    let all = DatabaseEngine::all();
    assert_eq!(all.len(), 7);
    assert!(all.contains(&DatabaseEngine::MongoDB));
    assert!(all.contains(&DatabaseEngine::Redis));
    assert!(all.contains(&DatabaseEngine::Elasticsearch));
    assert!(all.contains(&DatabaseEngine::CouchDB));
    assert!(all.contains(&DatabaseEngine::Cassandra));
    assert!(all.contains(&DatabaseEngine::Memcached));
    assert!(all.contains(&DatabaseEngine::PostgreSQL));
}

#[test]
fn default_ports_are_correct() {
    assert_eq!(DatabaseEngine::MongoDB.default_port(), MONGODB_DEFAULT_PORT);
    assert_eq!(DatabaseEngine::Redis.default_port(), REDIS_DEFAULT_PORT);
    assert_eq!(
        DatabaseEngine::Elasticsearch.default_port(),
        ELASTICSEARCH_DEFAULT_PORT
    );
    assert_eq!(DatabaseEngine::CouchDB.default_port(), COUCHDB_DEFAULT_PORT);
    assert_eq!(
        DatabaseEngine::Cassandra.default_port(),
        CASSANDRA_DEFAULT_PORT
    );
    assert_eq!(
        DatabaseEngine::Memcached.default_port(),
        MEMCACHED_DEFAULT_PORT
    );
    assert_eq!(
        DatabaseEngine::PostgreSQL.default_port(),
        POSTGRES_DEFAULT_PORT
    );
}

#[test]
fn port_constants_match_well_known_values() {
    assert_eq!(MONGODB_DEFAULT_PORT, 27017);
    assert_eq!(REDIS_DEFAULT_PORT, 6379);
    assert_eq!(ELASTICSEARCH_DEFAULT_PORT, 9200);
    assert_eq!(COUCHDB_DEFAULT_PORT, 5984);
    assert_eq!(CASSANDRA_DEFAULT_PORT, 9042);
    assert_eq!(MEMCACHED_DEFAULT_PORT, 11211);
    assert_eq!(POSTGRES_DEFAULT_PORT, 5432);
}

#[test]
fn engine_display_names() {
    assert_eq!(format!("{}", DatabaseEngine::MongoDB), "MongoDB");
    assert_eq!(format!("{}", DatabaseEngine::Redis), "Redis");
    assert_eq!(
        format!("{}", DatabaseEngine::Elasticsearch),
        "Elasticsearch"
    );
    assert_eq!(format!("{}", DatabaseEngine::CouchDB), "CouchDB");
    assert_eq!(format!("{}", DatabaseEngine::Cassandra), "Cassandra");
    assert_eq!(format!("{}", DatabaseEngine::Memcached), "Memcached");
    assert_eq!(format!("{}", DatabaseEngine::PostgreSQL), "PostgreSQL");
}

#[test]
fn connection_string_mongodb_no_creds() {
    let cs = connection_string(DatabaseEngine::MongoDB, "10.0.0.1", 27017, None);
    assert_eq!(cs, "mongodb://10.0.0.1:27017/admin");
}

#[test]
fn connection_string_mongodb_with_creds() {
    let cred = DefaultCredential {
        username: "admin".into(),
        password: "secret".into(),
    };
    let cs = connection_string(DatabaseEngine::MongoDB, "db.local", 27017, Some(&cred));
    assert_eq!(cs, "mongodb://admin:secret@db.local:27017/admin");
}

#[test]
fn connection_string_redis_no_auth() {
    let cs = connection_string(DatabaseEngine::Redis, "cache.local", 6379, None);
    assert_eq!(cs, "redis://cache.local:6379/0");
}

#[test]
fn connection_string_redis_with_password() {
    let cred = DefaultCredential {
        username: "".into(),
        password: "r3dis".into(),
    };
    let cs = connection_string(DatabaseEngine::Redis, "cache.local", 6379, Some(&cred));
    assert_eq!(cs, "redis://:r3dis@cache.local:6379/0");
}

#[test]
fn connection_string_elasticsearch() {
    let cs = connection_string(DatabaseEngine::Elasticsearch, "es.local", 9200, None);
    assert_eq!(cs, "http://es.local:9200");
}

#[test]
fn connection_string_couchdb() {
    let cs = connection_string(DatabaseEngine::CouchDB, "couch.local", 5984, None);
    assert_eq!(cs, "http://couch.local:5984/_all_dbs");
}

#[test]
fn connection_string_cassandra() {
    let cs = connection_string(DatabaseEngine::Cassandra, "cass.local", 9042, None);
    assert_eq!(cs, "cassandra://cass.local:9042");
}

#[test]
fn connection_string_memcached() {
    let cs = connection_string(DatabaseEngine::Memcached, "mc.local", 11211, None);
    assert_eq!(cs, "memcached://mc.local:11211");
}

#[test]
fn connection_string_postgres_no_creds() {
    let cs = connection_string(DatabaseEngine::PostgreSQL, "pg.local", 5432, None);
    assert_eq!(cs, "postgresql://pg.local:5432/postgres");
}

#[test]
fn connection_string_postgres_with_creds() {
    let cred = DefaultCredential {
        username: "postgres".into(),
        password: "postgres".into(),
    };
    let cs = connection_string(DatabaseEngine::PostgreSQL, "pg.local", 5432, Some(&cred));
    assert_eq!(cs, "postgresql://postgres:postgres@pg.local:5432/postgres");
}

#[test]
fn default_credentials_mongodb_non_empty() {
    let creds = default_credentials(DatabaseEngine::MongoDB);
    assert!(creds.len() >= 3);
    assert!(creds.iter().any(|c| c.username == "admin"));
    assert!(creds.iter().any(|c| c.username == "root"));
}

#[test]
fn default_credentials_redis_includes_empty() {
    let creds = default_credentials(DatabaseEngine::Redis);
    assert!(creds.iter().any(|c| c.password.is_empty()));
}

#[test]
fn default_credentials_postgres() {
    let creds = default_credentials(DatabaseEngine::PostgreSQL);
    assert!(creds.iter().any(|c| c.username == "postgres"));
}

#[test]
fn default_credentials_memcached_is_empty() {
    let creds = default_credentials(DatabaseEngine::Memcached);
    assert!(creds.is_empty());
}

#[test]
fn sampling_commands_not_empty_for_all_engines() {
    for engine in DatabaseEngine::all() {
        let cmds = sampling_commands(*engine);
        assert!(
            !cmds.is_empty(),
            "sampling commands for {} should not be empty",
            engine
        );
    }
}

#[test]
fn sampling_commands_mongodb_includes_show_dbs() {
    let cmds = sampling_commands(DatabaseEngine::MongoDB);
    assert!(cmds.iter().any(|c| c.contains("show dbs")));
}

#[test]
fn sampling_commands_redis_includes_info() {
    let cmds = sampling_commands(DatabaseEngine::Redis);
    assert!(cmds.iter().any(|c| c.contains("INFO")));
}

#[test]
fn sampling_commands_elasticsearch_includes_cat_indices() {
    let cmds = sampling_commands(DatabaseEngine::Elasticsearch);
    assert!(cmds.iter().any(|c| c.contains("_cat/indices")));
}

#[test]
fn sampling_commands_couchdb_includes_all_dbs() {
    let cmds = sampling_commands(DatabaseEngine::CouchDB);
    assert!(cmds.iter().any(|c| c.contains("_all_dbs")));
}

#[test]
fn sampling_commands_cassandra_includes_keyspaces() {
    let cmds = sampling_commands(DatabaseEngine::Cassandra);
    assert!(cmds.iter().any(|c| c.contains("KEYSPACES")));
}

#[test]
fn sampling_commands_memcached_includes_stats() {
    let cmds = sampling_commands(DatabaseEngine::Memcached);
    assert!(cmds.iter().any(|c| c.contains("stats")));
}

#[test]
fn sampling_commands_postgres_includes_pg_database() {
    let cmds = sampling_commands(DatabaseEngine::PostgreSQL);
    assert!(cmds.iter().any(|c| c.contains("pg_database")));
}

#[test]
fn severity_critical_for_primary_databases() {
    assert_eq!(
        severity_for_engine(DatabaseEngine::MongoDB),
        ExposedDbSeverity::Critical
    );
    assert_eq!(
        severity_for_engine(DatabaseEngine::PostgreSQL),
        ExposedDbSeverity::Critical
    );
    assert_eq!(
        severity_for_engine(DatabaseEngine::CouchDB),
        ExposedDbSeverity::Critical
    );
    assert_eq!(
        severity_for_engine(DatabaseEngine::Cassandra),
        ExposedDbSeverity::Critical
    );
}

#[test]
fn severity_high_for_search_and_cache() {
    assert_eq!(
        severity_for_engine(DatabaseEngine::Elasticsearch),
        ExposedDbSeverity::High
    );
    assert_eq!(
        severity_for_engine(DatabaseEngine::Redis),
        ExposedDbSeverity::High
    );
}

#[test]
fn severity_medium_for_memcached() {
    assert_eq!(
        severity_for_engine(DatabaseEngine::Memcached),
        ExposedDbSeverity::Medium
    );
}

#[test]
fn severity_scores_are_ordered() {
    assert!(ExposedDbSeverity::Informational.score() < ExposedDbSeverity::Low.score());
    assert!(ExposedDbSeverity::Low.score() < ExposedDbSeverity::Medium.score());
    assert!(ExposedDbSeverity::Medium.score() < ExposedDbSeverity::High.score());
    assert!(ExposedDbSeverity::High.score() < ExposedDbSeverity::Critical.score());
    assert!((ExposedDbSeverity::Critical.score() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn build_probe_uses_default_port() {
    let probe = build_probe(DatabaseEngine::Redis, "redis.local", None);
    assert_eq!(probe.port, 6379);
    assert_eq!(probe.engine, DatabaseEngine::Redis);
    assert!(probe.connection_string.contains("redis.local:6379"));
}

#[test]
fn build_probe_respects_port_override() {
    let probe = build_probe(DatabaseEngine::Redis, "redis.local", Some(16379));
    assert_eq!(probe.port, 16379);
    assert!(probe.connection_string.contains("redis.local:16379"));
}

#[test]
fn build_all_probes_returns_all_engines() {
    let probes = build_all_probes("target.local");
    assert_eq!(probes.len(), 7);
    let engines: Vec<_> = probes.iter().map(|p| p.engine).collect();
    for e in DatabaseEngine::all() {
        assert!(engines.contains(e));
    }
}

#[test]
fn finding_from_probe_inherits_fields() {
    let probe = build_probe(DatabaseEngine::MongoDB, "db.target.com", None);
    let finding = finding_from_probe(&probe);
    assert_eq!(finding.engine, DatabaseEngine::MongoDB);
    assert_eq!(finding.host, "db.target.com");
    assert_eq!(finding.port, 27017);
    assert_eq!(finding.severity, ExposedDbSeverity::Critical);
    assert!(finding.detail.contains("MongoDB"));
    assert!(finding.detail.contains("no authentication"));
}

#[test]
fn scanner_builder_pattern() {
    let scanner = ExposedDbScanner::new("host.com")
        .with_port(DatabaseEngine::Redis, 16379)
        .with_port(DatabaseEngine::MongoDB, 37017);
    assert_eq!(scanner.host, "host.com");
    assert_eq!(scanner.port_overrides.len(), 2);
}

#[test]
fn scanner_probes_respect_overrides() {
    let scanner = ExposedDbScanner::new("host.com").with_port(DatabaseEngine::Redis, 16379);
    let probes = scanner.probes();
    let redis_probe = probes
        .iter()
        .find(|p| p.engine == DatabaseEngine::Redis)
        .unwrap();
    assert_eq!(redis_probe.port, 16379);
    let mongo_probe = probes
        .iter()
        .find(|p| p.engine == DatabaseEngine::MongoDB)
        .unwrap();
    assert_eq!(mongo_probe.port, MONGODB_DEFAULT_PORT);
}

#[test]
fn scanner_probes_for_subset() {
    let scanner = ExposedDbScanner::new("host.com");
    let subset = scanner.probes_for(&[DatabaseEngine::Redis, DatabaseEngine::Memcached]);
    assert_eq!(subset.len(), 2);
    assert!(subset.iter().all(|p| p.host == "host.com"));
}

#[test]
fn connection_string_memcached_ignores_creds() {
    let cred = DefaultCredential {
        username: "admin".into(),
        password: "pass".into(),
    };
    let cs = connection_string(DatabaseEngine::Memcached, "mc.local", 11211, Some(&cred));
    assert_eq!(cs, "memcached://mc.local:11211");
}

#[test]
fn elasticsearch_with_creds() {
    let cred = DefaultCredential {
        username: "elastic".into(),
        password: "changeme".into(),
    };
    let cs = connection_string(DatabaseEngine::Elasticsearch, "es.local", 9200, Some(&cred));
    assert_eq!(cs, "http://elastic:changeme@es.local:9200");
}

#[test]
fn couchdb_with_creds() {
    let cred = DefaultCredential {
        username: "admin".into(),
        password: "admin".into(),
    };
    let cs = connection_string(DatabaseEngine::CouchDB, "couch.local", 5984, Some(&cred));
    assert_eq!(cs, "http://admin:admin@couch.local:5984/_all_dbs");
}

#[test]
fn cassandra_with_creds() {
    let cred = DefaultCredential {
        username: "cassandra".into(),
        password: "cassandra".into(),
    };
    let cs = connection_string(DatabaseEngine::Cassandra, "cass.local", 9042, Some(&cred));
    assert_eq!(cs, "cassandra://cassandra:cassandra@cass.local:9042");
}

#[test]
fn all_probes_have_non_empty_sampling_commands() {
    let probes = build_all_probes("test.host");
    for probe in &probes {
        assert!(
            !probe.sampling_commands.is_empty(),
            "{} probe has empty sampling commands",
            probe.engine
        );
    }
}

#[test]
fn all_probes_have_connection_strings() {
    let probes = build_all_probes("test.host");
    for probe in &probes {
        assert!(
            !probe.connection_string.is_empty(),
            "{} probe has empty connection string",
            probe.engine
        );
    }
}

#[test]
fn finding_detail_mentions_host_and_port() {
    let probe = build_probe(
        DatabaseEngine::Elasticsearch,
        "search.target.io",
        Some(9201),
    );
    let finding = finding_from_probe(&probe);
    assert!(finding.detail.contains("search.target.io"));
    assert!(finding.detail.contains("9201"));
}
