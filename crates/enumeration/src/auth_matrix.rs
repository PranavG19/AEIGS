use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Credential {
    pub label: String,
    pub privilege_level: PrivilegeLevel,
    pub auth_header: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PrivilegeLevel {
    Unauthenticated,
    User,
    Moderator,
    Admin,
    ServiceAccount,
}

impl std::fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Unauthenticated => "unauthenticated",
            Self::User => "user",
            Self::Moderator => "moderator",
            Self::Admin => "admin",
            Self::ServiceAccount => "service-account",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointAccess {
    pub endpoint: String,
    pub method: String,
    pub credential_label: String,
    pub status_code: u16,
}

#[derive(Debug, Clone)]
pub struct AuthorizationAnomaly {
    pub endpoint: String,
    pub method: String,
    pub low_privilege_credential: String,
    pub low_privilege_level: PrivilegeLevel,
    pub low_privilege_status: u16,
    pub high_privilege_credential: String,
    pub high_privilege_level: PrivilegeLevel,
    pub high_privilege_status: u16,
    pub anomaly_type: AnomalyType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyType {
    PotentialIdor,
    PrivilegeEscalation,
    MissingAuthentication,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::PotentialIdor => "potential-idor",
            Self::PrivilegeEscalation => "privilege-escalation",
            Self::MissingAuthentication => "missing-authentication",
        };
        write!(f, "{label}")
    }
}

pub struct AuthorizationMatrix {
    credentials: Vec<Credential>,
    access_results: Vec<EndpointAccess>,
}

impl AuthorizationMatrix {
    pub fn new(credentials: Vec<Credential>) -> Self {
        Self {
            credentials,
            access_results: Vec::new(),
        }
    }

    pub fn record_access(&mut self, access: EndpointAccess) {
        self.access_results.push(access);
    }

    pub fn record_access_batch(&mut self, accesses: Vec<EndpointAccess>) {
        self.access_results.extend(accesses);
    }

    pub fn credentials(&self) -> &[Credential] {
        &self.credentials
    }

    pub fn access_results(&self) -> &[EndpointAccess] {
        &self.access_results
    }

    pub fn status_for(&self, endpoint: &str, method: &str, credential_label: &str) -> Option<u16> {
        self.access_results.iter().find_map(|a| {
            if a.endpoint == endpoint
                && a.method == method
                && a.credential_label == credential_label
            {
                Some(a.status_code)
            } else {
                None
            }
        })
    }

    pub fn build_matrix_table(&self) -> HashMap<(String, String), HashMap<String, u16>> {
        let mut table: HashMap<(String, String), HashMap<String, u16>> = HashMap::new();

        for access in &self.access_results {
            let key = (access.endpoint.clone(), access.method.clone());
            table
                .entry(key)
                .or_default()
                .insert(access.credential_label.clone(), access.status_code);
        }

        table
    }

    pub fn detect_anomalies(&self) -> Vec<AuthorizationAnomaly> {
        let mut anomalies = Vec::new();
        let table = self.build_matrix_table();

        let credential_map: HashMap<&str, &Credential> = self
            .credentials
            .iter()
            .map(|c| (c.label.as_str(), c))
            .collect();

        for ((endpoint, method), statuses) in &table {
            for (low_label, &low_status) in statuses {
                let low_cred = match credential_map.get(low_label.as_str()) {
                    Some(c) => c,
                    None => continue,
                };

                for (high_label, &high_status) in statuses {
                    let high_cred = match credential_map.get(high_label.as_str()) {
                        Some(c) => c,
                        None => continue,
                    };

                    if low_cred.privilege_level >= high_cred.privilege_level {
                        continue;
                    }

                    if is_success(low_status) && is_success(high_status) {
                        let anomaly_type = classify_anomaly(low_cred.privilege_level, endpoint);

                        anomalies.push(AuthorizationAnomaly {
                            endpoint: endpoint.clone(),
                            method: method.clone(),
                            low_privilege_credential: low_label.clone(),
                            low_privilege_level: low_cred.privilege_level,
                            low_privilege_status: low_status,
                            high_privilege_credential: high_label.clone(),
                            high_privilege_level: high_cred.privilege_level,
                            high_privilege_status: high_status,
                            anomaly_type,
                        });
                    }
                }
            }
        }

        anomalies
    }

    pub fn endpoint_count(&self) -> usize {
        let table = self.build_matrix_table();
        table.len()
    }
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn classify_anomaly(low_privilege: PrivilegeLevel, endpoint: &str) -> AnomalyType {
    if low_privilege == PrivilegeLevel::Unauthenticated {
        return AnomalyType::MissingAuthentication;
    }

    let admin_indicators = ["admin", "manage", "config", "setting", "dashboard"];
    let is_admin_endpoint = admin_indicators
        .iter()
        .any(|ind| endpoint.to_lowercase().contains(ind));

    if is_admin_endpoint {
        AnomalyType::PrivilegeEscalation
    } else {
        AnomalyType::PotentialIdor
    }
}
