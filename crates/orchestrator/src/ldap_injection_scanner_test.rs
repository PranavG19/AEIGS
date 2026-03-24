use crate::ldap_injection_scanner::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_ldap_indicators("");
    assert!(issues.is_empty());
}

#[test]
fn detects_ldap_endpoint_exposed() {
    let body = "config: ldap://directory.example.com/dc=example,dc=com";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapEndpointExposed));
}

#[test]
fn detects_ldaps_endpoint_exposed() {
    let body = "secure endpoint: ldaps://ldap.corp.example.com";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapEndpointExposed));
}

#[test]
fn detects_ldap_filter_objectclass() {
    let body = "search filter: (objectclass=person)";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapFilterPattern));
}

#[test]
fn detects_ldap_filter_cn() {
    let body = "query: (cn=admin)";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapFilterPattern));
}

#[test]
fn detects_ldap_filter_uid() {
    let body = "lookup: (uid=jdoe)";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapFilterPattern));
}

#[test]
fn detects_ldap_filter_sn() {
    let body = "search: (sn=Smith)";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapFilterPattern));
}

#[test]
fn detects_ldap_dn_exposed() {
    let body = "base dn: dc=example,dc=com,ou=Users";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapDnExposed));
}

#[test]
fn detects_ldap_port_389() {
    let body = "server running on host.example.com:389";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapPortExposed));
}

#[test]
fn detects_ldap_port_636() {
    let body = "LDAPS at host.example.com:636";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapPortExposed));
}

#[test]
fn detects_directory_listing_index_of() {
    let body = "<html><title>Index of /</title></html>";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::DirectoryListingEnabled));
}

#[test]
fn detects_directory_listing_parent() {
    let body = "<a href=\"..\">Parent Directory</a>";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::DirectoryListingEnabled));
}

#[test]
fn detects_ldap_error_naming_exception() {
    let body = "javax.naming.NamingException: LDAP response read timed out";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapErrorMessage));
}

#[test]
fn detects_ldap_error_ldapexception() {
    let body = "Caught LDAPException during search: invalid filter";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapErrorMessage));
}

#[test]
fn detects_ldap_config_bind() {
    let body = "result = ldap_bind($conn, $dn, $password);";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapConfigExposed));
}

#[test]
fn detects_ldap_config_search() {
    let body = "$sr = ldap_search($ds, $dn, $filter);";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapConfigExposed));
}

#[test]
fn detects_ldap_config_connect() {
    let body = "$ds = ldap_connect('ldap.example.com');";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapConfigExposed));
}

#[test]
fn detects_active_directory_samaccountname() {
    let body = "filter: (samaccountname=admin)";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::ActiveDirectoryPattern));
}

#[test]
fn detects_active_directory_userprincipalname() {
    let body = "attribute: userprincipalname=admin@corp.local";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::ActiveDirectoryPattern));
}

#[test]
fn detects_active_directory_memberof() {
    let body = "memberof: CN=Domain Admins,CN=Users,DC=corp,DC=local";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::ActiveDirectoryPattern));
}

#[test]
fn no_false_positive_clean_html() {
    let body = "<html><head><title>Welcome</title></head><body>Hello world</body></html>";
    let issues = analyze_ldap_indicators(body);
    assert!(issues.is_empty());
}

#[test]
fn multiple_indicators_detected() {
    let body = r#"
        ldap://directory.example.com:389
        base: dc=example,dc=com
        filter: (objectclass=person)
        error: javax.naming.NamingException
    "#;
    let issues = analyze_ldap_indicators(body);
    assert!(issues.contains(&LdapInjectionIssue::LdapEndpointExposed));
    assert!(issues.contains(&LdapInjectionIssue::LdapFilterPattern));
    assert!(issues.contains(&LdapInjectionIssue::LdapDnExposed));
    assert!(issues.contains(&LdapInjectionIssue::LdapPortExposed));
    assert!(issues.contains(&LdapInjectionIssue::LdapErrorMessage));
}

#[test]
fn indicator_severity_error_message_highest() {
    assert_eq!(
        ldap_indicator_severity(&LdapInjectionIssue::LdapErrorMessage),
        8.0
    );
}

#[test]
fn indicator_severity_config_exposed() {
    assert_eq!(
        ldap_indicator_severity(&LdapInjectionIssue::LdapConfigExposed),
        7.5
    );
}

#[test]
fn indicator_severity_endpoint_exposed() {
    assert_eq!(
        ldap_indicator_severity(&LdapInjectionIssue::LdapEndpointExposed),
        7.0
    );
}

#[test]
fn indicator_severity_filter_pattern() {
    assert_eq!(
        ldap_indicator_severity(&LdapInjectionIssue::LdapFilterPattern),
        7.0
    );
}

#[test]
fn indicator_severity_active_directory() {
    assert_eq!(
        ldap_indicator_severity(&LdapInjectionIssue::ActiveDirectoryPattern),
        6.5
    );
}

#[test]
fn indicator_severity_dn_exposed() {
    assert_eq!(
        ldap_indicator_severity(&LdapInjectionIssue::LdapDnExposed),
        6.0
    );
}

#[test]
fn indicator_severity_port_exposed() {
    assert_eq!(
        ldap_indicator_severity(&LdapInjectionIssue::LdapPortExposed),
        5.5
    );
}

#[test]
fn indicator_severity_directory_listing_lowest() {
    assert_eq!(
        ldap_indicator_severity(&LdapInjectionIssue::DirectoryListingEnabled),
        5.0
    );
}

#[test]
fn indicator_to_operations_creates_entries() {
    let issues = vec![
        LdapInjectionIssue::LdapEndpointExposed,
        LdapInjectionIssue::LdapErrorMessage,
    ];
    let mut seq = 0;
    let ops = ldap_indicator_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn indicator_to_operations_empty_vec() {
    let issues: Vec<LdapInjectionIssue> = vec![];
    let mut seq = 0;
    let ops = ldap_indicator_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn indicator_display_variants() {
    assert_eq!(
        LdapInjectionIssue::LdapEndpointExposed.to_string(),
        "ldap_endpoint_exposed"
    );
    assert_eq!(
        LdapInjectionIssue::LdapFilterPattern.to_string(),
        "ldap_filter_pattern"
    );
    assert_eq!(
        LdapInjectionIssue::LdapDnExposed.to_string(),
        "ldap_dn_exposed"
    );
    assert_eq!(
        LdapInjectionIssue::LdapPortExposed.to_string(),
        "ldap_port_exposed"
    );
    assert_eq!(
        LdapInjectionIssue::DirectoryListingEnabled.to_string(),
        "directory_listing_enabled"
    );
    assert_eq!(
        LdapInjectionIssue::LdapErrorMessage.to_string(),
        "ldap_error_message"
    );
    assert_eq!(
        LdapInjectionIssue::LdapConfigExposed.to_string(),
        "ldap_config_exposed"
    );
    assert_eq!(
        LdapInjectionIssue::ActiveDirectoryPattern.to_string(),
        "active_directory_pattern"
    );
}

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_ldap_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_detects_injection_vector() {
    let body = r#"
        $username = $_GET['user'];
        $filter = "(uid=$username)";
        $result = ldap_search($conn, $base, $filter);
    "#;
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapInjectionVector));
}

#[test]
fn security_detects_injection_vector_req_body() {
    let body = r#"
        const username = req.body.username;
        const filter = `(cn=${username})`;
        const results = ldap.search(baseDN, { filter });
    "#;
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapInjectionVector));
}

#[test]
fn security_detects_anonymous_bind() {
    let body = r#"ldap_bind($conn, "cn=anonymous", password="")"#;
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapAnonymousBind));
}

#[test]
fn security_detects_anonymous_bind_keyword() {
    let body = "connection.bind({ dn: 'anonymous', password: '' })";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapAnonymousBind));
}

#[test]
fn security_detects_cleartext_ldap() {
    let body = r#"$ds = ldap_connect("ldap://directory.example.com"); ldap_bind($ds);"#;
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapCleartext));
}

#[test]
fn security_no_cleartext_for_ldaps() {
    let body = r#"$ds = ldap_connect("ldaps://directory.example.com"); ldap_bind($ds);"#;
    let issues = analyze_ldap_security(body);
    assert!(!issues.contains(&LdapSecurityIssue::LdapCleartext));
}

#[test]
fn security_detects_credential_exposed() {
    let body = r#"
        bindDN = "cn=admin,dc=example,dc=com"
        bindPassword = "s3cretP@ss"
    "#;
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapCredentialExposed));
}

#[test]
fn security_detects_credential_exposed_underscore() {
    let body = r#"
        bind_dn: cn=admin,dc=corp,dc=local
        ldap_password: hunter2
    "#;
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapCredentialExposed));
}

#[test]
fn security_detects_enumeration() {
    let body = "LDAP error: user not found in directory";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapEnumeration));
}

#[test]
fn security_detects_enumeration_no_such_object() {
    let body = "LDAP: No such object in directory tree";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapEnumeration));
}

#[test]
fn security_detects_wildcard_objectclass() {
    let body = "filter: (objectclass=*)";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapWildcard));
}

#[test]
fn security_detects_wildcard_cn() {
    let body = "search: (cn=*)";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapWildcard));
}

#[test]
fn security_detects_modify_access() {
    let body = "$result = ldap_modify($conn, $dn, $entry);";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapModifyAccess));
}

#[test]
fn security_detects_add_access() {
    let body = "ldap_add($conn, $dn, $entry);";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapModifyAccess));
}

#[test]
fn security_detects_delete_access() {
    let body = "ldap_delete($conn, $dn);";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapModifyAccess));
}

#[test]
fn security_detects_schema_exposed_subschema() {
    let body = "cn=subschema contains the directory schema definitions";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapSchemaExposed));
}

#[test]
fn security_detects_schema_exposed_objectclasses() {
    let body = "objectclasses: ( 2.5.6.6 NAME 'person' )";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapSchemaExposed));
}

#[test]
fn security_detects_schema_exposed_attributetypes() {
    let body = "attributetypes: ( 2.5.4.3 NAME 'cn' )";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapSchemaExposed));
}

#[test]
fn security_detects_referral_chasing() {
    let body = "LDAP config: referral chasing enabled";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapReferralChasing));
}

#[test]
fn security_detects_referral_chase_keyword() {
    let body = "ldap: chase referrals = true";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapReferralChasing));
}

#[test]
fn security_detects_attribute_exfiltration_function() {
    let body = "$attrs = ldap_get_attributes($conn, $entry);";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapAttributeExfiltration));
}

#[test]
fn security_detects_attribute_exfiltration_wildcard() {
    let body = "ldap search attributes: * (all)";
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapAttributeExfiltration));
}

#[test]
fn security_no_false_positive_clean_html() {
    let body =
        "<html><head><title>Login</title></head><body><form action='/login'></form></body></html>";
    let issues = analyze_ldap_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_severity_credential_exposed_highest() {
    assert_eq!(
        ldap_security_severity(&LdapSecurityIssue::LdapCredentialExposed),
        9.0
    );
}

#[test]
fn security_severity_injection_vector() {
    assert_eq!(
        ldap_security_severity(&LdapSecurityIssue::LdapInjectionVector),
        8.5
    );
}

#[test]
fn security_severity_anonymous_bind() {
    assert_eq!(
        ldap_security_severity(&LdapSecurityIssue::LdapAnonymousBind),
        8.0
    );
}

#[test]
fn security_severity_modify_access() {
    assert_eq!(
        ldap_security_severity(&LdapSecurityIssue::LdapModifyAccess),
        7.5
    );
}

#[test]
fn security_severity_cleartext() {
    assert_eq!(
        ldap_security_severity(&LdapSecurityIssue::LdapCleartext),
        7.0
    );
}

#[test]
fn security_severity_enumeration() {
    assert_eq!(
        ldap_security_severity(&LdapSecurityIssue::LdapEnumeration),
        7.0
    );
}

#[test]
fn security_severity_wildcard() {
    assert_eq!(
        ldap_security_severity(&LdapSecurityIssue::LdapWildcard),
        6.5
    );
}

#[test]
fn security_severity_referral_chasing() {
    assert_eq!(
        ldap_security_severity(&LdapSecurityIssue::LdapReferralChasing),
        6.5
    );
}

#[test]
fn security_severity_schema_exposed() {
    assert_eq!(
        ldap_security_severity(&LdapSecurityIssue::LdapSchemaExposed),
        6.0
    );
}

#[test]
fn security_severity_attribute_exfiltration_lowest() {
    assert_eq!(
        ldap_security_severity(&LdapSecurityIssue::LdapAttributeExfiltration),
        5.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        LdapSecurityIssue::LdapInjectionVector,
        LdapSecurityIssue::LdapCredentialExposed,
        LdapSecurityIssue::LdapAnonymousBind,
    ];
    let mut seq = 0;
    let ops = ldap_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_to_operations_empty_vec() {
    let issues: Vec<LdapSecurityIssue> = vec![];
    let mut seq = 0;
    let ops = ldap_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_display_variants() {
    assert_eq!(
        LdapSecurityIssue::LdapInjectionVector.to_string(),
        "ldap_injection_vector"
    );
    assert_eq!(
        LdapSecurityIssue::LdapAnonymousBind.to_string(),
        "ldap_anonymous_bind"
    );
    assert_eq!(
        LdapSecurityIssue::LdapCleartext.to_string(),
        "ldap_cleartext"
    );
    assert_eq!(
        LdapSecurityIssue::LdapCredentialExposed.to_string(),
        "ldap_credential_exposed"
    );
    assert_eq!(
        LdapSecurityIssue::LdapEnumeration.to_string(),
        "ldap_enumeration"
    );
    assert_eq!(LdapSecurityIssue::LdapWildcard.to_string(), "ldap_wildcard");
    assert_eq!(
        LdapSecurityIssue::LdapModifyAccess.to_string(),
        "ldap_modify_access"
    );
    assert_eq!(
        LdapSecurityIssue::LdapSchemaExposed.to_string(),
        "ldap_schema_exposed"
    );
    assert_eq!(
        LdapSecurityIssue::LdapReferralChasing.to_string(),
        "ldap_referral_chasing"
    );
    assert_eq!(
        LdapSecurityIssue::LdapAttributeExfiltration.to_string(),
        "ldap_attribute_exfiltration"
    );
}

#[test]
fn security_combined_multiple_issues() {
    let body = r#"
        $user = $_POST['username'];
        $filter = "(uid=$user)";
        $conn = ldap_connect("ldap://dir.example.com");
        ldap_bind($conn, "cn=admin", password="");
        $sr = ldap_search($conn, "dc=example,dc=com", $filter);
        $result = ldap_modify($conn, $dn, $attrs);
    "#;
    let issues = analyze_ldap_security(body);
    assert!(issues.contains(&LdapSecurityIssue::LdapInjectionVector));
    assert!(issues.contains(&LdapSecurityIssue::LdapAnonymousBind));
    assert!(issues.contains(&LdapSecurityIssue::LdapCleartext));
    assert!(issues.contains(&LdapSecurityIssue::LdapModifyAccess));
}
