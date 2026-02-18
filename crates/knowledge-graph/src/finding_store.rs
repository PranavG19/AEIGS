use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::operation::ModuleIdentifier;
use std::collections::HashMap;

pub struct FindingStore {
    findings: Vec<FindingData>,
    node_index: HashMap<u64, Vec<u64>>,
    class_index: HashMap<VulnerabilityClass, Vec<u64>>,
}

impl FindingStore {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            node_index: HashMap::new(),
            class_index: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        linked_node_ids: Vec<u64>,
        vulnerability_class: VulnerabilityClass,
        severity: f64,
        confidence: f64,
        certificate: Vec<u8>,
        provenance_module: ModuleIdentifier,
        timestamp_unix_ms: u64,
    ) -> u64 {
        let id = self.findings.len() as u64;
        let finding = FindingData {
            id,
            linked_node_ids: linked_node_ids.clone(),
            vulnerability_class,
            severity,
            confidence,
            certificate,
            provenance_module,
            timestamp_unix_ms,
        };

        for node_id in &linked_node_ids {
            self.node_index.entry(*node_id).or_default().push(id);
        }
        self.class_index
            .entry(vulnerability_class)
            .or_default()
            .push(id);

        self.findings.push(finding);
        id
    }

    pub fn get(&self, id: u64) -> Option<&FindingData> {
        self.findings.get(id as usize)
    }

    pub fn findings_for_node(&self, node_id: u64) -> &[u64] {
        self.node_index
            .get(&node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn findings_by_class(&self, vulnerability_class: VulnerabilityClass) -> &[u64] {
        self.class_index
            .get(&vulnerability_class)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn count(&self) -> usize {
        self.findings.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &FindingData> {
        self.findings.iter()
    }
}

impl Default for FindingStore {
    fn default() -> Self {
        Self::new()
    }
}
