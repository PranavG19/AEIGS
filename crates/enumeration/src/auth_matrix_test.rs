#[cfg(test)]
mod tests {
    use crate::auth_matrix::{
        AnomalyType, AuthorizationMatrix, Credential, EndpointAccess, PrivilegeLevel,
    };

    fn test_credentials() -> Vec<Credential> {
        vec![
            Credential {
                label: "unauth".to_string(),
                privilege_level: PrivilegeLevel::Unauthenticated,
                auth_header: None,
            },
            Credential {
                label: "user".to_string(),
                privilege_level: PrivilegeLevel::User,
                auth_header: Some("Bearer user-token".to_string()),
            },
            Credential {
                label: "admin".to_string(),
                privilege_level: PrivilegeLevel::Admin,
                auth_header: Some("Bearer admin-token".to_string()),
            },
        ]
    }

    fn access(endpoint: &str, method: &str, cred: &str, status: u16) -> EndpointAccess {
        EndpointAccess {
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            credential_label: cred.to_string(),
            status_code: status,
        }
    }

    #[test]
    fn create_empty_matrix() {
        let matrix = AuthorizationMatrix::new(test_credentials());
        assert_eq!(matrix.credentials().len(), 3);
        assert!(matrix.access_results().is_empty());
    }

    #[test]
    fn record_and_query_access() {
        let mut matrix = AuthorizationMatrix::new(test_credentials());
        matrix.record_access(access("/users", "GET", "admin", 200));

        assert_eq!(matrix.status_for("/users", "GET", "admin"), Some(200));
        assert_eq!(matrix.status_for("/users", "GET", "user"), None);
    }

    #[test]
    fn record_batch_access() {
        let mut matrix = AuthorizationMatrix::new(test_credentials());
        matrix.record_access_batch(vec![
            access("/users", "GET", "unauth", 401),
            access("/users", "GET", "user", 200),
            access("/users", "GET", "admin", 200),
        ]);

        assert_eq!(matrix.access_results().len(), 3);
        assert_eq!(matrix.status_for("/users", "GET", "unauth"), Some(401));
        assert_eq!(matrix.status_for("/users", "GET", "user"), Some(200));
    }

    #[test]
    fn build_matrix_table() {
        let mut matrix = AuthorizationMatrix::new(test_credentials());
        matrix.record_access_batch(vec![
            access("/users", "GET", "unauth", 401),
            access("/users", "GET", "user", 200),
            access("/users", "GET", "admin", 200),
            access("/users", "DELETE", "admin", 200),
        ]);

        let table = matrix.build_matrix_table();
        assert_eq!(table.len(), 2);
        assert_eq!(
            *table
                .get(&("/users".to_string(), "GET".to_string()))
                .unwrap()
                .get("unauth")
                .unwrap(),
            401
        );
    }

    #[test]
    fn detect_no_anomalies_when_access_is_properly_restricted() {
        let mut matrix = AuthorizationMatrix::new(test_credentials());
        matrix.record_access_batch(vec![
            access("/admin/config", "GET", "unauth", 401),
            access("/admin/config", "GET", "user", 403),
            access("/admin/config", "GET", "admin", 200),
        ]);

        let anomalies = matrix.detect_anomalies();
        assert!(anomalies.is_empty());
    }

    #[test]
    fn detect_missing_authentication() {
        let mut matrix = AuthorizationMatrix::new(test_credentials());
        matrix.record_access_batch(vec![
            access("/users", "GET", "unauth", 200),
            access("/users", "GET", "user", 200),
            access("/users", "GET", "admin", 200),
        ]);

        let anomalies = matrix.detect_anomalies();
        let unauth_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::MissingAuthentication)
            .collect();
        assert!(!unauth_anomalies.is_empty());
    }

    #[test]
    fn detect_privilege_escalation_on_admin_endpoint() {
        let mut matrix = AuthorizationMatrix::new(test_credentials());
        matrix.record_access_batch(vec![
            access("/admin/config", "GET", "unauth", 401),
            access("/admin/config", "GET", "user", 200),
            access("/admin/config", "GET", "admin", 200),
        ]);

        let anomalies = matrix.detect_anomalies();
        let priv_esc: Vec<_> = anomalies
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::PrivilegeEscalation)
            .collect();
        assert!(!priv_esc.is_empty());
        assert_eq!(priv_esc[0].low_privilege_credential, "user");
    }

    #[test]
    fn detect_potential_idor() {
        let mut matrix = AuthorizationMatrix::new(test_credentials());
        matrix.record_access_batch(vec![
            access("/users/123", "DELETE", "unauth", 401),
            access("/users/123", "DELETE", "user", 200),
            access("/users/123", "DELETE", "admin", 200),
        ]);

        let anomalies = matrix.detect_anomalies();
        let idor: Vec<_> = anomalies
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::PotentialIdor)
            .collect();
        assert!(!idor.is_empty());
    }

    #[test]
    fn endpoint_count() {
        let mut matrix = AuthorizationMatrix::new(test_credentials());
        matrix.record_access_batch(vec![
            access("/users", "GET", "admin", 200),
            access("/users", "POST", "admin", 201),
            access("/items", "GET", "admin", 200),
        ]);
        assert_eq!(matrix.endpoint_count(), 3);
    }

    #[test]
    fn privilege_level_ordering() {
        assert!(PrivilegeLevel::Unauthenticated < PrivilegeLevel::User);
        assert!(PrivilegeLevel::User < PrivilegeLevel::Moderator);
        assert!(PrivilegeLevel::Moderator < PrivilegeLevel::Admin);
        assert!(PrivilegeLevel::Admin < PrivilegeLevel::ServiceAccount);
    }

    #[test]
    fn privilege_level_display() {
        assert_eq!(
            PrivilegeLevel::Unauthenticated.to_string(),
            "unauthenticated"
        );
        assert_eq!(PrivilegeLevel::User.to_string(), "user");
        assert_eq!(PrivilegeLevel::Moderator.to_string(), "moderator");
        assert_eq!(PrivilegeLevel::Admin.to_string(), "admin");
        assert_eq!(
            PrivilegeLevel::ServiceAccount.to_string(),
            "service-account"
        );
    }

    #[test]
    fn anomaly_type_display() {
        assert_eq!(AnomalyType::PotentialIdor.to_string(), "potential-idor");
        assert_eq!(
            AnomalyType::PrivilegeEscalation.to_string(),
            "privilege-escalation"
        );
        assert_eq!(
            AnomalyType::MissingAuthentication.to_string(),
            "missing-authentication"
        );
    }

    #[test]
    fn no_anomaly_when_only_high_privilege_succeeds() {
        let mut matrix = AuthorizationMatrix::new(test_credentials());
        matrix.record_access_batch(vec![
            access("/admin/settings", "POST", "unauth", 401),
            access("/admin/settings", "POST", "user", 403),
            access("/admin/settings", "POST", "admin", 200),
        ]);

        let anomalies = matrix.detect_anomalies();
        assert!(anomalies.is_empty());
    }

    #[test]
    fn admin_indicator_detection_case_insensitive() {
        let mut matrix = AuthorizationMatrix::new(test_credentials());
        matrix.record_access_batch(vec![
            access("/Dashboard/manage", "GET", "user", 200),
            access("/Dashboard/manage", "GET", "admin", 200),
        ]);

        let anomalies = matrix.detect_anomalies();
        assert!(!anomalies.is_empty());
        assert_eq!(anomalies[0].anomaly_type, AnomalyType::PrivilegeEscalation);
    }
}
