use std::collections::{HashMap, HashSet};

/// Infrastructure artifact type in the temporal graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactType {
    Domain,
    IpAddress,
    Certificate,
    Asn,
    Nameserver,
    Registrar,
    WhoisOrg,
    MxRecord,
    SubnetBlock,
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain => write!(f, "Domain"),
            Self::IpAddress => write!(f, "IP Address"),
            Self::Certificate => write!(f, "Certificate"),
            Self::Asn => write!(f, "ASN"),
            Self::Nameserver => write!(f, "Nameserver"),
            Self::Registrar => write!(f, "Registrar"),
            Self::WhoisOrg => write!(f, "WHOIS Organization"),
            Self::MxRecord => write!(f, "MX Record"),
            Self::SubnetBlock => write!(f, "Subnet Block"),
        }
    }
}

/// Source of temporal data for an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataSource {
    DnsHistory,
    WhoisSnapshot,
    CertificateTransparency,
    BgpAnnouncement,
    PassiveDns,
    WebArchive,
}

impl std::fmt::Display for DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DnsHistory => write!(f, "DNS History"),
            Self::WhoisSnapshot => write!(f, "WHOIS Snapshot"),
            Self::CertificateTransparency => write!(f, "CT Log"),
            Self::BgpAnnouncement => write!(f, "BGP Announcement"),
            Self::PassiveDns => write!(f, "Passive DNS"),
            Self::WebArchive => write!(f, "Web Archive"),
        }
    }
}

/// Confidence in a temporal relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CorrelationConfidence {
    Low,
    Medium,
    High,
    Definitive,
}

impl std::fmt::Display for CorrelationConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Definitive => write!(f, "Definitive"),
        }
    }
}

/// A single node in the temporal infrastructure graph.
#[derive(Debug, Clone, PartialEq)]
pub struct TemporalArtifact {
    pub id: u64,
    pub artifact_type: ArtifactType,
    pub value: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub sources: Vec<DataSource>,
    pub metadata: HashMap<String, String>,
}

/// A time-bounded edge between two artifacts: they co-existed in overlapping windows.
#[derive(Debug, Clone, PartialEq)]
pub struct TemporalEdge {
    pub source_id: u64,
    pub target_id: u64,
    pub relationship: TemporalRelationship,
    pub overlap_start_ms: u64,
    pub overlap_end_ms: u64,
    pub data_sources: Vec<DataSource>,
    pub confidence: CorrelationConfidence,
}

/// The kind of temporal relationship between two artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemporalRelationship {
    ResolvedTo,
    SharedCertificate,
    SameAsn,
    SameRegistrar,
    SameSubnet,
    SequentialRegistration,
    SharedNameserver,
    SharedMx,
    IpReuse,
    CertificateReissue,
}

impl std::fmt::Display for TemporalRelationship {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResolvedTo => write!(f, "Resolved To"),
            Self::SharedCertificate => write!(f, "Shared Certificate"),
            Self::SameAsn => write!(f, "Same ASN"),
            Self::SameRegistrar => write!(f, "Same Registrar"),
            Self::SameSubnet => write!(f, "Same /24 Subnet"),
            Self::SequentialRegistration => write!(f, "Sequential Registration"),
            Self::SharedNameserver => write!(f, "Shared Nameserver"),
            Self::SharedMx => write!(f, "Shared MX"),
            Self::IpReuse => write!(f, "IP Reuse"),
            Self::CertificateReissue => write!(f, "Certificate Reissue"),
        }
    }
}

/// A detected infrastructure reuse pattern, the core output.
#[derive(Debug, Clone, PartialEq)]
pub struct InfraReusePattern {
    pub pattern_id: String,
    pub involved_artifacts: Vec<u64>,
    pub pattern_type: ReusePatternType,
    pub confidence: CorrelationConfidence,
    pub temporal_gap_ms: u64,
    pub description: String,
    pub indicators: Vec<String>,
}

/// Classification of reuse patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReusePatternType {
    DomainRotation,
    IpRecycling,
    CertificateChain,
    RegistrarClustering,
    AsnHopping,
    SubnetReuse,
    NameserverPivot,
    ShadowInfrastructure,
}

impl std::fmt::Display for ReusePatternType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DomainRotation => write!(f, "Domain Rotation"),
            Self::IpRecycling => write!(f, "IP Recycling"),
            Self::CertificateChain => write!(f, "Certificate Chain Reuse"),
            Self::RegistrarClustering => write!(f, "Registrar Clustering"),
            Self::AsnHopping => write!(f, "ASN Hopping"),
            Self::SubnetReuse => write!(f, "Subnet Reuse"),
            Self::NameserverPivot => write!(f, "Nameserver Pivot"),
            Self::ShadowInfrastructure => write!(f, "Shadow Infrastructure"),
        }
    }
}

/// DNS resolution record with timestamp.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    pub domain: String,
    pub resolved_ip: String,
    pub record_type: String,
    pub timestamp_ms: u64,
    pub source: DataSource,
}

/// WHOIS snapshot for a domain at a point in time.
#[derive(Debug, Clone, PartialEq)]
pub struct WhoisSnapshot {
    pub domain: String,
    pub registrar: String,
    pub registrant_org: Option<String>,
    pub nameservers: Vec<String>,
    pub creation_date_ms: u64,
    pub expiry_date_ms: u64,
    pub snapshot_timestamp_ms: u64,
}

/// Certificate Transparency log entry.
#[derive(Debug, Clone, PartialEq)]
pub struct CtLogEntry {
    pub fingerprint: String,
    pub domains: Vec<String>,
    pub issuer: String,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub log_timestamp_ms: u64,
}

/// BGP announcement snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct BgpAnnouncement {
    pub prefix: String,
    pub asn: u32,
    pub as_name: Option<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// Configuration for the temporal correlator.
#[derive(Debug, Clone)]
pub struct CorrelatorConfig {
    pub max_temporal_gap_ms: u64,
    pub subnet_mask_bits: u8,
    pub min_co_occurrence_count: usize,
    pub sequential_registration_window_ms: u64,
    pub min_pattern_confidence: CorrelationConfidence,
}

impl Default for CorrelatorConfig {
    fn default() -> Self {
        Self {
            max_temporal_gap_ms: 7 * 24 * 3600 * 1000,
            subnet_mask_bits: 24,
            min_co_occurrence_count: 2,
            sequential_registration_window_ms: 72 * 3600 * 1000,
            min_pattern_confidence: CorrelationConfidence::Medium,
        }
    }
}

impl CorrelatorConfig {
    pub fn with_max_temporal_gap_ms(mut self, gap: u64) -> Self {
        self.max_temporal_gap_ms = gap;
        self
    }

    pub fn with_subnet_mask_bits(mut self, bits: u8) -> Self {
        self.subnet_mask_bits = bits.min(32);
        self
    }

    pub fn with_min_co_occurrence_count(mut self, count: usize) -> Self {
        self.min_co_occurrence_count = count.max(1);
        self
    }

    pub fn with_sequential_registration_window_ms(mut self, window: u64) -> Self {
        self.sequential_registration_window_ms = window;
        self
    }
}

/// Output of a full temporal correlation analysis.
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    pub artifacts: Vec<TemporalArtifact>,
    pub edges: Vec<TemporalEdge>,
    pub patterns: Vec<InfraReusePattern>,
    pub timeline_span_ms: u64,
}

/// The temporal infrastructure correlator.
/// Cross-correlates DNS, WHOIS, CT, and BGP data to build a temporal graph
/// and detect infrastructure reuse patterns invisible to point-in-time scans.
pub struct TemporalCorrelator {
    config: CorrelatorConfig,
    artifacts: Vec<TemporalArtifact>,
    edges: Vec<TemporalEdge>,
    next_id: u64,
    value_index: HashMap<String, u64>,
}

impl TemporalCorrelator {
    pub fn new(config: CorrelatorConfig) -> Self {
        Self {
            config,
            artifacts: Vec::new(),
            edges: Vec::new(),
            next_id: 0,
            value_index: HashMap::new(),
        }
    }

    /// Ingest DNS history records into the temporal graph.
    pub fn ingest_dns_records(&mut self, records: &[DnsRecord]) {
        for record in records {
            let domain_id = self.ensure_artifact(
                ArtifactType::Domain,
                &record.domain,
                record.timestamp_ms,
                record.source,
            );
            let ip_id = self.ensure_artifact(
                ArtifactType::IpAddress,
                &record.resolved_ip,
                record.timestamp_ms,
                record.source,
            );
            self.add_edge(
                domain_id,
                ip_id,
                TemporalRelationship::ResolvedTo,
                record.timestamp_ms,
                record.timestamp_ms,
                record.source,
                CorrelationConfidence::Definitive,
            );
        }
    }

    /// Ingest WHOIS snapshots into the temporal graph.
    pub fn ingest_whois_snapshots(&mut self, snapshots: &[WhoisSnapshot]) {
        for snap in snapshots {
            let domain_id = self.ensure_artifact(
                ArtifactType::Domain,
                &snap.domain,
                snap.snapshot_timestamp_ms,
                DataSource::WhoisSnapshot,
            );
            let registrar_id = self.ensure_artifact(
                ArtifactType::Registrar,
                &snap.registrar,
                snap.snapshot_timestamp_ms,
                DataSource::WhoisSnapshot,
            );
            self.add_edge(
                domain_id,
                registrar_id,
                TemporalRelationship::SameRegistrar,
                snap.creation_date_ms,
                snap.expiry_date_ms,
                DataSource::WhoisSnapshot,
                CorrelationConfidence::Definitive,
            );
            if let Some(org) = &snap.registrant_org {
                let org_id = self.ensure_artifact(
                    ArtifactType::WhoisOrg,
                    org,
                    snap.snapshot_timestamp_ms,
                    DataSource::WhoisSnapshot,
                );
                self.add_edge(
                    domain_id,
                    org_id,
                    TemporalRelationship::SameRegistrar,
                    snap.creation_date_ms,
                    snap.expiry_date_ms,
                    DataSource::WhoisSnapshot,
                    CorrelationConfidence::High,
                );
            }
            for ns in &snap.nameservers {
                let ns_id = self.ensure_artifact(
                    ArtifactType::Nameserver,
                    ns,
                    snap.snapshot_timestamp_ms,
                    DataSource::WhoisSnapshot,
                );
                self.add_edge(
                    domain_id,
                    ns_id,
                    TemporalRelationship::SharedNameserver,
                    snap.creation_date_ms,
                    snap.expiry_date_ms,
                    DataSource::WhoisSnapshot,
                    CorrelationConfidence::Definitive,
                );
            }
        }
    }

    /// Ingest CT log entries into the temporal graph.
    pub fn ingest_ct_logs(&mut self, entries: &[CtLogEntry]) {
        for entry in entries {
            let cert_id = self.ensure_artifact(
                ArtifactType::Certificate,
                &entry.fingerprint,
                entry.log_timestamp_ms,
                DataSource::CertificateTransparency,
            );
            for domain in &entry.domains {
                let domain_id = self.ensure_artifact(
                    ArtifactType::Domain,
                    domain,
                    entry.log_timestamp_ms,
                    DataSource::CertificateTransparency,
                );
                self.add_edge(
                    domain_id,
                    cert_id,
                    TemporalRelationship::SharedCertificate,
                    entry.not_before_ms,
                    entry.not_after_ms,
                    DataSource::CertificateTransparency,
                    CorrelationConfidence::Definitive,
                );
            }
        }
    }

    /// Ingest BGP announcements into the temporal graph.
    pub fn ingest_bgp_announcements(&mut self, announcements: &[BgpAnnouncement]) {
        for ann in announcements {
            let prefix_id = self.ensure_artifact(
                ArtifactType::SubnetBlock,
                &ann.prefix,
                ann.first_seen_ms,
                DataSource::BgpAnnouncement,
            );
            let asn_str = format!("AS{}", ann.asn);
            let asn_id = self.ensure_artifact(
                ArtifactType::Asn,
                &asn_str,
                ann.first_seen_ms,
                DataSource::BgpAnnouncement,
            );
            self.add_edge(
                prefix_id,
                asn_id,
                TemporalRelationship::SameAsn,
                ann.first_seen_ms,
                ann.last_seen_ms,
                DataSource::BgpAnnouncement,
                CorrelationConfidence::Definitive,
            );
        }
    }

    /// Run full correlation analysis: builds edges, detects reuse patterns.
    pub fn correlate(&mut self) -> CorrelationResult {
        self.detect_subnet_relationships();
        self.detect_sequential_registrations();
        self.detect_ip_reuse();
        let patterns = self.detect_reuse_patterns();

        let span = self.compute_timeline_span();
        CorrelationResult {
            artifacts: self.artifacts.clone(),
            edges: self.edges.clone(),
            patterns,
            timeline_span_ms: span,
        }
    }

    /// Detect IP addresses that share a /24 subnet.
    fn detect_subnet_relationships(&mut self) {
        let ip_artifacts: Vec<(u64, String)> = self
            .artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::IpAddress)
            .map(|a| (a.id, a.value.clone()))
            .collect();

        let mut subnet_groups: HashMap<String, Vec<u64>> = HashMap::new();
        for (id, ip) in &ip_artifacts {
            if let Some(subnet) = extract_subnet(ip, self.config.subnet_mask_bits) {
                subnet_groups.entry(subnet).or_default().push(*id);
            }
        }

        for (_subnet, ids) in &subnet_groups {
            if ids.len() < 2 {
                continue;
            }
            for i in 0..ids.len() {
                for j in (i + 1)..ids.len() {
                    let a = &self.artifacts[ids[i] as usize];
                    let b = &self.artifacts[ids[j] as usize];
                    if self.time_windows_overlap(
                        a.first_seen_ms,
                        a.last_seen_ms,
                        b.first_seen_ms,
                        b.last_seen_ms,
                    ) {
                        self.add_edge(
                            ids[i],
                            ids[j],
                            TemporalRelationship::SameSubnet,
                            a.first_seen_ms.max(b.first_seen_ms),
                            a.last_seen_ms.min(b.last_seen_ms),
                            DataSource::PassiveDns,
                            CorrelationConfidence::Medium,
                        );
                    }
                }
            }
        }
    }

    /// Detect domains registered in close temporal sequence (e.g., same campaign).
    fn detect_sequential_registrations(&mut self) {
        let mut domain_artifacts: Vec<(u64, u64)> = self
            .artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::Domain)
            .map(|a| (a.id, a.first_seen_ms))
            .collect();
        domain_artifacts.sort_by_key(|&(_, ts)| ts);

        for i in 0..domain_artifacts.len() {
            for j in (i + 1)..domain_artifacts.len() {
                let gap = domain_artifacts[j].1.saturating_sub(domain_artifacts[i].1);
                if gap > self.config.sequential_registration_window_ms {
                    break;
                }
                if gap > 0 {
                    self.add_edge(
                        domain_artifacts[i].0,
                        domain_artifacts[j].0,
                        TemporalRelationship::SequentialRegistration,
                        domain_artifacts[i].1,
                        domain_artifacts[j].1,
                        DataSource::WhoisSnapshot,
                        if gap < 24 * 3600 * 1000 {
                            CorrelationConfidence::High
                        } else {
                            CorrelationConfidence::Medium
                        },
                    );
                }
            }
        }
    }

    /// Detect IPs reused by different domains across time.
    fn detect_ip_reuse(&mut self) {
        let mut ip_to_domains: HashMap<u64, Vec<u64>> = HashMap::new();
        for edge in &self.edges {
            if edge.relationship == TemporalRelationship::ResolvedTo {
                ip_to_domains
                    .entry(edge.target_id)
                    .or_default()
                    .push(edge.source_id);
            }
        }

        let mut new_edges = Vec::new();
        for (_ip_id, domain_ids) in &ip_to_domains {
            if domain_ids.len() < 2 {
                continue;
            }
            let unique: HashSet<u64> = domain_ids.iter().copied().collect();
            let unique_vec: Vec<u64> = unique.into_iter().collect();
            for i in 0..unique_vec.len() {
                for j in (i + 1)..unique_vec.len() {
                    let a = &self.artifacts[unique_vec[i] as usize];
                    let b = &self.artifacts[unique_vec[j] as usize];
                    new_edges.push(TemporalEdge {
                        source_id: unique_vec[i],
                        target_id: unique_vec[j],
                        relationship: TemporalRelationship::IpReuse,
                        overlap_start_ms: a.first_seen_ms.min(b.first_seen_ms),
                        overlap_end_ms: a.last_seen_ms.max(b.last_seen_ms),
                        data_sources: vec![DataSource::PassiveDns],
                        confidence: CorrelationConfidence::High,
                    });
                }
            }
        }
        self.edges.extend(new_edges);
    }

    /// Detect infrastructure reuse patterns from the temporal graph.
    fn detect_reuse_patterns(&self) -> Vec<InfraReusePattern> {
        let mut patterns = Vec::new();
        patterns.extend(self.detect_domain_rotation());
        patterns.extend(self.detect_registrar_clustering());
        patterns.extend(self.detect_subnet_reuse());
        patterns.extend(self.detect_nameserver_pivots());
        patterns
    }

    fn detect_domain_rotation(&self) -> Vec<InfraReusePattern> {
        let sequential_edges: Vec<&TemporalEdge> = self
            .edges
            .iter()
            .filter(|e| e.relationship == TemporalRelationship::SequentialRegistration)
            .collect();

        if sequential_edges.len() < self.config.min_co_occurrence_count {
            return Vec::new();
        }

        let mut involved: HashSet<u64> = HashSet::new();
        let mut indicators = Vec::new();
        for edge in &sequential_edges {
            involved.insert(edge.source_id);
            involved.insert(edge.target_id);
            let src = &self.artifacts[edge.source_id as usize];
            let tgt = &self.artifacts[edge.target_id as usize];
            let gap_hrs = (edge.overlap_end_ms - edge.overlap_start_ms) / (3600 * 1000);
            indicators.push(format!(
                "{} registered {}h after {}",
                tgt.value, gap_hrs, src.value
            ));
        }

        if involved.len() >= self.config.min_co_occurrence_count {
            let min_ts = sequential_edges
                .iter()
                .map(|e| e.overlap_start_ms)
                .min()
                .unwrap_or(0);
            let max_ts = sequential_edges
                .iter()
                .map(|e| e.overlap_end_ms)
                .max()
                .unwrap_or(0);
            vec![InfraReusePattern {
                pattern_id: format!("domain-rotation-{}", min_ts),
                involved_artifacts: involved.into_iter().collect(),
                pattern_type: ReusePatternType::DomainRotation,
                confidence: CorrelationConfidence::High,
                temporal_gap_ms: max_ts.saturating_sub(min_ts),
                description: format!(
                    "Detected {} domains registered in rapid succession",
                    sequential_edges.len() + 1
                ),
                indicators,
            }]
        } else {
            Vec::new()
        }
    }

    fn detect_registrar_clustering(&self) -> Vec<InfraReusePattern> {
        let mut registrar_domains: HashMap<u64, Vec<u64>> = HashMap::new();
        for edge in &self.edges {
            if edge.relationship == TemporalRelationship::SameRegistrar {
                let src = &self.artifacts[edge.source_id as usize];
                let tgt = &self.artifacts[edge.target_id as usize];
                if src.artifact_type == ArtifactType::Domain
                    && tgt.artifact_type == ArtifactType::Registrar
                {
                    registrar_domains
                        .entry(edge.target_id)
                        .or_default()
                        .push(edge.source_id);
                }
            }
        }

        let mut patterns = Vec::new();
        for (registrar_id, domain_ids) in &registrar_domains {
            if domain_ids.len() >= self.config.min_co_occurrence_count {
                let registrar = &self.artifacts[*registrar_id as usize];
                let mut involved = domain_ids.clone();
                involved.push(*registrar_id);
                let indicators: Vec<String> = domain_ids
                    .iter()
                    .map(|id| {
                        let d = &self.artifacts[*id as usize];
                        format!("{} registered via {}", d.value, registrar.value)
                    })
                    .collect();
                patterns.push(InfraReusePattern {
                    pattern_id: format!("registrar-cluster-{}", registrar_id),
                    involved_artifacts: involved,
                    pattern_type: ReusePatternType::RegistrarClustering,
                    confidence: CorrelationConfidence::Medium,
                    temporal_gap_ms: 0,
                    description: format!(
                        "{} domains clustered at registrar {}",
                        domain_ids.len(),
                        registrar.value
                    ),
                    indicators,
                });
            }
        }
        patterns
    }

    fn detect_subnet_reuse(&self) -> Vec<InfraReusePattern> {
        let subnet_edges: Vec<&TemporalEdge> = self
            .edges
            .iter()
            .filter(|e| e.relationship == TemporalRelationship::SameSubnet)
            .collect();

        if subnet_edges.len() < self.config.min_co_occurrence_count {
            return Vec::new();
        }

        let mut involved: HashSet<u64> = HashSet::new();
        for edge in &subnet_edges {
            involved.insert(edge.source_id);
            involved.insert(edge.target_id);
        }

        vec![InfraReusePattern {
            pattern_id: format!("subnet-reuse-{}", subnet_edges.len()),
            involved_artifacts: involved.into_iter().collect(),
            pattern_type: ReusePatternType::SubnetReuse,
            confidence: CorrelationConfidence::Medium,
            temporal_gap_ms: 0,
            description: format!(
                "{} IPs sharing /24 subnet co-occurred temporally",
                subnet_edges.len()
            ),
            indicators: subnet_edges
                .iter()
                .map(|e| {
                    let src = &self.artifacts[e.source_id as usize];
                    let tgt = &self.artifacts[e.target_id as usize];
                    format!("{} and {} in same /24", src.value, tgt.value)
                })
                .collect(),
        }]
    }

    fn detect_nameserver_pivots(&self) -> Vec<InfraReusePattern> {
        let mut ns_domains: HashMap<u64, Vec<u64>> = HashMap::new();
        for edge in &self.edges {
            if edge.relationship == TemporalRelationship::SharedNameserver {
                ns_domains
                    .entry(edge.target_id)
                    .or_default()
                    .push(edge.source_id);
            }
        }

        let mut patterns = Vec::new();
        for (ns_id, domain_ids) in &ns_domains {
            if domain_ids.len() >= self.config.min_co_occurrence_count {
                let ns = &self.artifacts[*ns_id as usize];
                let mut involved = domain_ids.clone();
                involved.push(*ns_id);
                patterns.push(InfraReusePattern {
                    pattern_id: format!("ns-pivot-{}", ns_id),
                    involved_artifacts: involved,
                    pattern_type: ReusePatternType::NameserverPivot,
                    confidence: CorrelationConfidence::High,
                    temporal_gap_ms: 0,
                    description: format!(
                        "{} domains share nameserver {}",
                        domain_ids.len(),
                        ns.value
                    ),
                    indicators: domain_ids
                        .iter()
                        .map(|id| {
                            let d = &self.artifacts[*id as usize];
                            format!("{} → {}", d.value, ns.value)
                        })
                        .collect(),
                });
            }
        }
        patterns
    }

    fn ensure_artifact(
        &mut self,
        artifact_type: ArtifactType,
        value: &str,
        timestamp_ms: u64,
        source: DataSource,
    ) -> u64 {
        let key = format!("{:?}:{}", artifact_type, value);
        if let Some(&id) = self.value_index.get(&key) {
            let artifact = &mut self.artifacts[id as usize];
            artifact.first_seen_ms = artifact.first_seen_ms.min(timestamp_ms);
            artifact.last_seen_ms = artifact.last_seen_ms.max(timestamp_ms);
            if !artifact.sources.contains(&source) {
                artifact.sources.push(source);
            }
            return id;
        }

        let id = self.next_id;
        self.next_id += 1;
        self.value_index.insert(key, id);
        self.artifacts.push(TemporalArtifact {
            id,
            artifact_type,
            value: value.to_string(),
            first_seen_ms: timestamp_ms,
            last_seen_ms: timestamp_ms,
            sources: vec![source],
            metadata: HashMap::new(),
        });
        id
    }

    #[allow(clippy::too_many_arguments)]
    fn add_edge(
        &mut self,
        source_id: u64,
        target_id: u64,
        relationship: TemporalRelationship,
        overlap_start_ms: u64,
        overlap_end_ms: u64,
        source: DataSource,
        confidence: CorrelationConfidence,
    ) {
        self.edges.push(TemporalEdge {
            source_id,
            target_id,
            relationship,
            overlap_start_ms,
            overlap_end_ms,
            data_sources: vec![source],
            confidence,
        });
    }

    fn time_windows_overlap(&self, a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
        a_start <= b_end && b_start <= a_end
    }

    fn compute_timeline_span(&self) -> u64 {
        if self.artifacts.is_empty() {
            return 0;
        }
        let min = self
            .artifacts
            .iter()
            .map(|a| a.first_seen_ms)
            .min()
            .unwrap_or(0);
        let max = self
            .artifacts
            .iter()
            .map(|a| a.last_seen_ms)
            .max()
            .unwrap_or(0);
        max.saturating_sub(min)
    }

    /// Return read access to all artifacts.
    pub fn artifacts(&self) -> &[TemporalArtifact] {
        &self.artifacts
    }

    /// Return read access to all edges.
    pub fn edges(&self) -> &[TemporalEdge] {
        &self.edges
    }
}

/// Extract /N subnet from an IPv4 address string.
fn extract_subnet(ip: &str, mask_bits: u8) -> Option<String> {
    let octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return None;
    }
    let ip_u32 = (octets[0] as u32) << 24
        | (octets[1] as u32) << 16
        | (octets[2] as u32) << 8
        | (octets[3] as u32);
    let mask = if mask_bits >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - mask_bits)
    };
    let subnet = ip_u32 & mask;
    Some(format!(
        "{}.{}.{}.{}/{}",
        (subnet >> 24) & 0xFF,
        (subnet >> 16) & 0xFF,
        (subnet >> 8) & 0xFF,
        subnet & 0xFF,
        mask_bits
    ))
}
