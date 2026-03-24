use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum LdapInjectionIssue {
    LdapEndpointExposed,
    LdapFilterPattern,
    LdapDnExposed,
    LdapPortExposed,
    DirectoryListingEnabled,
    LdapErrorMessage,
    LdapConfigExposed,
    ActiveDirectoryPattern,
}

impl std::fmt::Display for LdapInjectionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LdapEndpointExposed => write!(f, "ldap_endpoint_exposed"),
            Self::LdapFilterPattern => write!(f, "ldap_filter_pattern"),
            Self::LdapDnExposed => write!(f, "ldap_dn_exposed"),
            Self::LdapPortExposed => write!(f, "ldap_port_exposed"),
            Self::DirectoryListingEnabled => write!(f, "directory_listing_enabled"),
            Self::LdapErrorMessage => write!(f, "ldap_error_message"),
            Self::LdapConfigExposed => write!(f, "ldap_config_exposed"),
            Self::ActiveDirectoryPattern => write!(f, "active_directory_pattern"),
        }
    }
}

pub fn scan_ldap_indicators(target: &str) -> Vec<LdapInjectionIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_ldap_indicators(&body)
}

pub fn analyze_ldap_indicators(body: &str) -> Vec<LdapInjectionIssue> {
    let lower = body.to_ascii_lowercase();
    let mut issues = Vec::new();

    if lower.contains("ldap://") || lower.contains("ldaps://") {
        issues.push(LdapInjectionIssue::LdapEndpointExposed);
    }

    if lower.contains("(objectclass=")
        || lower.contains("(cn=")
        || lower.contains("(uid=")
        || lower.contains("(sn=")
    {
        issues.push(LdapInjectionIssue::LdapFilterPattern);
    }

    if lower.contains("dc=") || lower.contains("ou=") || lower.contains("cn=") {
        issues.push(LdapInjectionIssue::LdapDnExposed);
    }

    if lower.contains(":389") || lower.contains(":636") {
        issues.push(LdapInjectionIssue::LdapPortExposed);
    }

    if lower.contains("index of /")
        || lower.contains("directory listing")
        || lower.contains("parent directory")
    {
        issues.push(LdapInjectionIssue::DirectoryListingEnabled);
    }

    if lower.contains("javax.naming.namingexception")
        || lower.contains("ldapexception")
        || lower.contains("ldap_")
    {
        issues.push(LdapInjectionIssue::LdapErrorMessage);
    }

    if lower.contains("ldap_bind")
        || lower.contains("ldap_search")
        || lower.contains("ldap_connect")
    {
        issues.push(LdapInjectionIssue::LdapConfigExposed);
    }

    if lower.contains("samaccountname")
        || lower.contains("userprincipalname")
        || lower.contains("memberof")
    {
        issues.push(LdapInjectionIssue::ActiveDirectoryPattern);
    }

    issues
}

pub fn ldap_indicator_severity(issue: &LdapInjectionIssue) -> f64 {
    match issue {
        LdapInjectionIssue::LdapErrorMessage => 8.0,
        LdapInjectionIssue::LdapConfigExposed => 7.5,
        LdapInjectionIssue::LdapEndpointExposed => 7.0,
        LdapInjectionIssue::LdapFilterPattern => 7.0,
        LdapInjectionIssue::ActiveDirectoryPattern => 6.5,
        LdapInjectionIssue::LdapDnExposed => 6.0,
        LdapInjectionIssue::LdapPortExposed => 5.5,
        LdapInjectionIssue::DirectoryListingEnabled => 5.0,
    }
}

pub fn ldap_indicator_to_operations(
    issues: &[LdapInjectionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InsufficientInputValidation,
                ldap_indicator_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum LdapSecurityIssue {
    LdapInjectionVector,
    LdapAnonymousBind,
    LdapCleartext,
    LdapCredentialExposed,
    LdapEnumeration,
    LdapWildcard,
    LdapModifyAccess,
    LdapSchemaExposed,
    LdapReferralChasing,
    LdapAttributeExfiltration,
}

impl std::fmt::Display for LdapSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LdapInjectionVector => write!(f, "ldap_injection_vector"),
            Self::LdapAnonymousBind => write!(f, "ldap_anonymous_bind"),
            Self::LdapCleartext => write!(f, "ldap_cleartext"),
            Self::LdapCredentialExposed => write!(f, "ldap_credential_exposed"),
            Self::LdapEnumeration => write!(f, "ldap_enumeration"),
            Self::LdapWildcard => write!(f, "ldap_wildcard"),
            Self::LdapModifyAccess => write!(f, "ldap_modify_access"),
            Self::LdapSchemaExposed => write!(f, "ldap_schema_exposed"),
            Self::LdapReferralChasing => write!(f, "ldap_referral_chasing"),
            Self::LdapAttributeExfiltration => write!(f, "ldap_attribute_exfiltration"),
        }
    }
}

pub fn analyze_ldap_security(body: &str) -> Vec<LdapSecurityIssue> {
    let lower = body.to_ascii_lowercase();
    let mut issues = Vec::new();

    if (lower.contains("request.get")
        || lower.contains("request.post")
        || lower.contains("req.body")
        || lower.contains("req.query")
        || lower.contains("$_get")
        || lower.contains("$_post")
        || lower.contains("params["))
        && (lower.contains("ldap_search")
            || lower.contains("ldap.search")
            || lower.contains("ldap_filter")
            || lower.contains("search_filter"))
    {
        issues.push(LdapSecurityIssue::LdapInjectionVector);
    }

    if (lower.contains("bind") || lower.contains("ldap_bind"))
        && (lower.contains("anonymous")
            || lower.contains("password=\"\"")
            || lower.contains("password=''")
            || lower.contains("password: \"\"")
            || lower.contains("password: ''"))
    {
        issues.push(LdapSecurityIssue::LdapAnonymousBind);
    }

    if lower.contains("ldap://")
        && (lower.contains("bind") || lower.contains("connect") || lower.contains("ldap_connect"))
    {
        issues.push(LdapSecurityIssue::LdapCleartext);
    }

    if (lower.contains("binddn") || lower.contains("bind_dn"))
        && (lower.contains("bindpassword")
            || lower.contains("bind_password")
            || lower.contains("ldap_password"))
    {
        issues.push(LdapSecurityIssue::LdapCredentialExposed);
    }

    if (lower.contains("user not found") || lower.contains("no such object"))
        && (lower.contains("ldap") || lower.contains("directory"))
    {
        issues.push(LdapSecurityIssue::LdapEnumeration);
    }

    if lower.contains("(objectclass=*)") || lower.contains("(cn=*)") {
        issues.push(LdapSecurityIssue::LdapWildcard);
    }

    if lower.contains("ldap_modify") || lower.contains("ldap_add") || lower.contains("ldap_delete")
    {
        issues.push(LdapSecurityIssue::LdapModifyAccess);
    }

    if lower.contains("subschema")
        || lower.contains("objectclasses")
        || lower.contains("attributetypes")
    {
        issues.push(LdapSecurityIssue::LdapSchemaExposed);
    }

    if (lower.contains("referral") || lower.contains("chase"))
        && (lower.contains("ldap") || lower.contains("directory"))
    {
        issues.push(LdapSecurityIssue::LdapReferralChasing);
    }

    if lower.contains("ldap_get_attributes")
        || (lower.contains("ldap") && lower.contains("attributes") && lower.contains("*"))
    {
        issues.push(LdapSecurityIssue::LdapAttributeExfiltration);
    }

    issues
}

pub fn ldap_security_severity(issue: &LdapSecurityIssue) -> f64 {
    match issue {
        LdapSecurityIssue::LdapCredentialExposed => 9.0,
        LdapSecurityIssue::LdapInjectionVector => 8.5,
        LdapSecurityIssue::LdapAnonymousBind => 8.0,
        LdapSecurityIssue::LdapModifyAccess => 7.5,
        LdapSecurityIssue::LdapCleartext => 7.0,
        LdapSecurityIssue::LdapEnumeration => 7.0,
        LdapSecurityIssue::LdapWildcard => 6.5,
        LdapSecurityIssue::LdapReferralChasing => 6.5,
        LdapSecurityIssue::LdapSchemaExposed => 6.0,
        LdapSecurityIssue::LdapAttributeExfiltration => 5.5,
    }
}

pub fn ldap_security_to_operations(
    issues: &[LdapSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InsufficientInputValidation,
                ldap_security_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[cfg(test)]
#[path = "ldap_injection_scanner_test.rs"]
mod ldap_injection_scanner_test;
