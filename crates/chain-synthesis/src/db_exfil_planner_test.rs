use crate::db_exfil_planner::*;

// =========================================================================
// Schema enumeration
// =========================================================================

fn make_config(dbms: DbmsType, technique: SqliTechnique) -> DbExfilConfig {
    DbExfilConfig {
        dbms,
        technique,
        injection_point: "id=1".to_string(),
        max_rows_per_table: 500,
        sample_large_tables: true,
        large_table_threshold: 10_000,
        columns_per_query: 3,
        parallel_tables: false,
    }
}

#[test]
fn test_schema_enum_mysql() {
    let config = make_config(DbmsType::MySql, SqliTechnique::UnionBased);
    let queries = generate_schema_enumeration(&config).unwrap();
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].query_type, QueryType::SchemaEnumeration);
    assert!(queries[0].payload.contains("information_schema.tables"));
    assert!(queries[0].payload.contains("UNION SELECT"));
}

#[test]
fn test_schema_enum_postgres() {
    let config = make_config(DbmsType::PostgreSql, SqliTechnique::ErrorBased);
    let queries = generate_schema_enumeration(&config).unwrap();
    assert_eq!(queries.len(), 1);
    assert!(queries[0].payload.contains("pg_tables"));
    assert!(queries[0].payload.contains("EXTRACTVALUE"));
}

#[test]
fn test_schema_enum_mssql() {
    let config = make_config(DbmsType::MsSql, SqliTechnique::Stacked);
    let queries = generate_schema_enumeration(&config).unwrap();
    assert_eq!(queries.len(), 1);
    assert!(queries[0].payload.contains("sys.tables"));
    assert!(queries[0].payload.contains(";"));
}

#[test]
fn test_schema_enum_sqlite() {
    let config = make_config(DbmsType::Sqlite, SqliTechnique::UnionBased);
    let queries = generate_schema_enumeration(&config).unwrap();
    assert_eq!(queries.len(), 1);
    assert!(queries[0].payload.contains("sqlite_master"));
}

// =========================================================================
// Column enumeration
// =========================================================================

#[test]
fn test_column_enum_generates_queries() {
    let config = make_config(DbmsType::MySql, SqliTechnique::UnionBased);
    let queries = generate_column_enumeration("users", &config).unwrap();
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].query_type, QueryType::ColumnEnumeration);
    assert!(queries[0].payload.contains("information_schema.columns"));
    assert!(queries[0].payload.contains("users"));
}

#[test]
fn test_column_enum_oracle() {
    let config = make_config(DbmsType::Oracle, SqliTechnique::ErrorBased);
    let queries = generate_column_enumeration("accounts", &config).unwrap();
    assert!(queries[0].payload.contains("all_tab_columns"));
    assert!(queries[0].payload.contains("UPPER"));
}

#[test]
fn test_column_enum_sqlite() {
    let config = make_config(DbmsType::Sqlite, SqliTechnique::UnionBased);
    let queries = generate_column_enumeration("products", &config).unwrap();
    assert!(queries[0].payload.contains("PRAGMA table_info"));
}

// =========================================================================
// Table priority classification
// =========================================================================

#[test]
fn test_classify_table_priority() {
    assert_eq!(classify_table_priority("users"), TablePriority::Critical);
    assert_eq!(
        classify_table_priority("user_credentials"),
        TablePriority::Critical
    );
    assert_eq!(classify_table_priority("api_keys"), TablePriority::Critical);
    assert_eq!(
        classify_table_priority("passwords"),
        TablePriority::Critical
    );
    assert_eq!(
        classify_table_priority("admin_panel"),
        TablePriority::Critical
    );

    assert_eq!(classify_table_priority("sessions"), TablePriority::High);
    assert_eq!(classify_table_priority("auth_tokens"), TablePriority::High);
    assert_eq!(
        classify_table_priority("role_assignments"),
        TablePriority::High
    );
    assert_eq!(classify_table_priority("permissions"), TablePriority::High);

    assert_eq!(classify_table_priority("audit_log"), TablePriority::Low);
    assert_eq!(
        classify_table_priority("analytics_events"),
        TablePriority::Low
    );
    assert_eq!(classify_table_priority("app_logs"), TablePriority::Low);

    assert_eq!(classify_table_priority("products"), TablePriority::Medium);
    assert_eq!(classify_table_priority("orders"), TablePriority::Medium);
    assert_eq!(classify_table_priority("invoices"), TablePriority::Medium);

    assert_eq!(
        classify_table_priority("schema_migrations"),
        TablePriority::Skip
    );
    assert_eq!(
        classify_table_priority("sqlite_sequence"),
        TablePriority::Skip
    );
}

// =========================================================================
// Sampling strategy selection
// =========================================================================

#[test]
fn test_sampling_strategy_selection() {
    assert_eq!(
        select_sampling_strategy(None, 500, 10_000),
        SamplingStrategy::Full,
    );
    assert_eq!(
        select_sampling_strategy(Some(100), 500, 10_000),
        SamplingStrategy::Full,
    );
    assert_eq!(
        select_sampling_strategy(Some(500), 500, 10_000),
        SamplingStrategy::Full,
    );
    assert_eq!(
        select_sampling_strategy(Some(2_000), 500, 10_000),
        SamplingStrategy::LimitOffset,
    );
    assert_eq!(
        select_sampling_strategy(Some(50_000), 500, 10_000),
        SamplingStrategy::RandomSample,
    );
}

// =========================================================================
// Table extraction planning
// =========================================================================

fn make_table(name: &str, cols: usize, rows: Option<u64>) -> DbTable {
    let columns = (0..cols)
        .map(|i| DbColumn {
            name: format!("col_{i}"),
            column_type: if i == 0 {
                ColumnType::Integer
            } else {
                ColumnType::Text
            },
            is_nullable: i > 0,
            is_key: i == 0,
        })
        .collect();

    DbTable {
        schema_name: "public".to_string(),
        table_name: name.to_string(),
        columns,
        estimated_row_count: rows,
        priority: classify_table_priority(name),
    }
}

#[test]
fn test_plan_table_extraction_union() {
    let table = make_table("users", 4, Some(50));
    let config = make_config(DbmsType::MySql, SqliTechnique::UnionBased);
    let plan = plan_table_extraction(&table, &config).unwrap();

    assert_eq!(plan.technique, SqliTechnique::UnionBased);
    assert_eq!(plan.sampling_strategy, SamplingStrategy::Full);
    assert!(plan.queries.len() >= 2);

    let has_row_count = plan
        .queries
        .iter()
        .any(|q| q.query_type == QueryType::RowCount);
    assert!(has_row_count);

    let has_data = plan
        .queries
        .iter()
        .any(|q| q.query_type == QueryType::DataExtraction);
    assert!(has_data);

    for q in &plan.queries {
        assert!(q.payload.contains("UNION SELECT"));
    }
}

#[test]
fn test_plan_table_extraction_blind() {
    let table = make_table("tokens", 2, Some(10));
    let config = make_config(DbmsType::PostgreSql, SqliTechnique::BlindBoolean);
    let plan = plan_table_extraction(&table, &config).unwrap();

    assert_eq!(plan.technique, SqliTechnique::BlindBoolean);
    for q in &plan.queries {
        assert!(q.payload.contains("CASE WHEN"));
    }
    assert!(plan.estimated_time_ms > 0);
}

#[test]
fn test_plan_table_extraction_blind_time() {
    let table = make_table("secrets", 2, Some(5));
    let config = make_config(DbmsType::MySql, SqliTechnique::BlindTime);
    let plan = plan_table_extraction(&table, &config).unwrap();

    for q in &plan.queries {
        assert!(q.payload.contains("SLEEP"));
    }
    assert!(plan.estimated_time_ms >= 15_000);
}

// =========================================================================
// Full database extraction plan
// =========================================================================

#[test]
fn test_plan_database_extraction_ordering() {
    let tables = vec![
        make_table("analytics_events", 3, Some(100)),
        make_table("user_credentials", 5, Some(200)),
        make_table("products", 4, Some(300)),
        make_table("auth_sessions", 3, Some(50)),
    ];
    let config = make_config(DbmsType::MySql, SqliTechnique::UnionBased);
    let plan = plan_database_extraction(&tables, &config).unwrap();

    assert_eq!(plan.extraction_order[0], "user_credentials");
    assert_eq!(plan.extraction_order[1], "auth_sessions");

    let crit_pos = plan
        .extraction_order
        .iter()
        .position(|n| n == "user_credentials")
        .unwrap();
    let low_pos = plan
        .extraction_order
        .iter()
        .position(|n| n == "analytics_events")
        .unwrap();
    assert!(crit_pos < low_pos);

    assert!(plan.total_queries > 0);
    assert!(plan.estimated_time_ms > 0);
    assert!(!plan.schema_queries.is_empty());
}

#[test]
fn test_plan_database_extraction_skips_system_tables() {
    let tables = vec![
        make_table("users", 3, Some(10)),
        make_table("sqlite_sequence", 2, Some(5)),
    ];
    let config = make_config(DbmsType::Sqlite, SqliTechnique::UnionBased);
    let plan = plan_database_extraction(&tables, &config).unwrap();

    assert_eq!(plan.table_plans.len(), 1);
    assert_eq!(plan.extraction_order, vec!["users"]);
}

#[test]
fn test_plan_database_extraction_empty_tables_error() {
    let config = make_config(DbmsType::MySql, SqliTechnique::UnionBased);
    let result = plan_database_extraction(&[], &config);
    assert_eq!(result.unwrap_err(), DbExfilError::NoTablesFound);
}

// =========================================================================
// Version fingerprint
// =========================================================================

#[test]
fn test_version_fingerprint_queries() {
    let mysql = generate_version_fingerprint(DbmsType::MySql);
    assert!(mysql.payload.contains("@@version"));
    assert_eq!(mysql.query_type, QueryType::VersionFingerprint);

    let pg = generate_version_fingerprint(DbmsType::PostgreSql);
    assert!(pg.payload.contains("version()"));

    let mssql = generate_version_fingerprint(DbmsType::MsSql);
    assert!(mssql.payload.contains("@@version"));

    let oracle = generate_version_fingerprint(DbmsType::Oracle);
    assert!(oracle.payload.contains("v$version"));

    let sqlite = generate_version_fingerprint(DbmsType::Sqlite);
    assert!(sqlite.payload.contains("sqlite_version()"));
}

// =========================================================================
// Technique wrapping
// =========================================================================

#[test]
fn test_technique_wrapping_union() {
    let config = make_config(DbmsType::MySql, SqliTechnique::UnionBased);
    let queries = generate_schema_enumeration(&config).unwrap();
    let payload = &queries[0].payload;
    assert!(payload.starts_with("id=1"));
    assert!(payload.contains("UNION SELECT"));
    assert!(payload.contains("NULL"));
    assert!(payload.ends_with("-- -"));
}

#[test]
fn test_technique_wrapping_error_based() {
    let config = make_config(DbmsType::MySql, SqliTechnique::ErrorBased);
    let queries = generate_schema_enumeration(&config).unwrap();
    let payload = &queries[0].payload;
    assert!(payload.contains("EXTRACTVALUE"));
    assert!(payload.contains("CONCAT(0x7e"));
}

#[test]
fn test_technique_wrapping_blind_boolean() {
    let config = make_config(DbmsType::MySql, SqliTechnique::BlindBoolean);
    let queries = generate_schema_enumeration(&config).unwrap();
    let payload = &queries[0].payload;
    assert!(payload.contains("CASE WHEN"));
    assert!(payload.contains("THEN 1 ELSE 0 END"));
}

#[test]
fn test_technique_wrapping_blind_time() {
    let config = make_config(DbmsType::MySql, SqliTechnique::BlindTime);
    let queries = generate_schema_enumeration(&config).unwrap();
    let payload = &queries[0].payload;
    assert!(payload.contains("IF("));
    assert!(payload.contains("SLEEP(2)"));
}

#[test]
fn test_technique_wrapping_stacked() {
    let config = make_config(DbmsType::MySql, SqliTechnique::Stacked);
    let queries = generate_schema_enumeration(&config).unwrap();
    let payload = &queries[0].payload;
    assert!(payload.contains("';"));
    assert!(payload.ends_with("-- -"));
}

// =========================================================================
// Display impls
// =========================================================================

#[test]
fn test_display_impls() {
    assert_eq!(format!("{}", DbmsType::MySql), "MySQL");
    assert_eq!(format!("{}", DbmsType::PostgreSql), "PostgreSQL");
    assert_eq!(format!("{}", DbmsType::MsSql), "MSSQL");
    assert_eq!(format!("{}", DbmsType::Oracle), "Oracle");
    assert_eq!(format!("{}", DbmsType::Sqlite), "SQLite");

    assert_eq!(format!("{}", SqliTechnique::UnionBased), "union-based");
    assert_eq!(format!("{}", SqliTechnique::BlindTime), "blind-time");
    assert_eq!(format!("{}", SqliTechnique::Stacked), "stacked");

    assert_eq!(format!("{}", ColumnType::Integer), "integer");
    assert_eq!(format!("{}", ColumnType::Blob), "blob");

    assert_eq!(format!("{}", TablePriority::Critical), "critical");
    assert_eq!(format!("{}", TablePriority::Skip), "skip");

    assert_eq!(
        format!("{}", QueryType::SchemaEnumeration),
        "schema-enumeration"
    );
    assert_eq!(
        format!("{}", QueryType::VersionFingerprint),
        "version-fingerprint"
    );

    assert_eq!(format!("{}", SamplingStrategy::Full), "full");
    assert_eq!(
        format!("{}", SamplingStrategy::RandomSample),
        "random-sample"
    );

    let err = DbExfilError::NoTablesFound;
    assert_eq!(format!("{err}"), "no tables found");

    let err = DbExfilError::InvalidConfig("bad".to_string());
    assert!(format!("{err}").contains("bad"));
}

// =========================================================================
// Invalid config
// =========================================================================

#[test]
fn test_invalid_config_zero_columns() {
    let config = DbExfilConfig {
        dbms: DbmsType::MySql,
        technique: SqliTechnique::UnionBased,
        injection_point: "id=1".to_string(),
        max_rows_per_table: 500,
        sample_large_tables: true,
        large_table_threshold: 10_000,
        columns_per_query: 0,
        parallel_tables: false,
    };
    let result = generate_schema_enumeration(&config);
    assert!(matches!(result, Err(DbExfilError::InvalidConfig(_))));
}

#[test]
fn test_invalid_config_empty_injection_point() {
    let config = DbExfilConfig {
        dbms: DbmsType::MySql,
        technique: SqliTechnique::UnionBased,
        injection_point: String::new(),
        max_rows_per_table: 500,
        sample_large_tables: true,
        large_table_threshold: 10_000,
        columns_per_query: 3,
        parallel_tables: false,
    };
    let result = generate_schema_enumeration(&config);
    assert!(matches!(result, Err(DbExfilError::InvalidConfig(_))));
}

#[test]
fn test_blob_columns_excluded_from_extraction() {
    let table = DbTable {
        schema_name: "public".to_string(),
        table_name: "documents".to_string(),
        columns: vec![
            DbColumn {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                is_nullable: false,
                is_key: true,
            },
            DbColumn {
                name: "content".to_string(),
                column_type: ColumnType::Blob,
                is_nullable: true,
                is_key: false,
            },
            DbColumn {
                name: "title".to_string(),
                column_type: ColumnType::Text,
                is_nullable: false,
                is_key: false,
            },
        ],
        estimated_row_count: Some(10),
        priority: TablePriority::Medium,
    };

    let config = make_config(DbmsType::MySql, SqliTechnique::UnionBased);
    let plan = plan_table_extraction(&table, &config).unwrap();

    for q in &plan.queries {
        if q.query_type == QueryType::DataExtraction {
            assert!(!q.payload.contains("content"));
            assert!(q.payload.contains("id"));
            assert!(q.payload.contains("title"));
        }
    }
}
