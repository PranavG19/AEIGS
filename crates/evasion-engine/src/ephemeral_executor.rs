use std::fmt;

use serde::{Deserialize, Serialize};

/// Cloud provider for ephemeral node provisioning.
///
/// Each variant maps to a specific Terraform provider block and instance
/// resource type used by `EphemeralExecutor::generate_terraform_config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    DigitalOcean,
    Vultr,
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aws => write!(f, "AWS"),
            Self::DigitalOcean => write!(f, "DigitalOcean"),
            Self::Vultr => write!(f, "Vultr"),
        }
    }
}

/// Specification for an ephemeral compute node.
///
/// Describes the cloud provider, instance type, and region where the node
/// will be provisioned. Passed to `EphemeralExecutor::new` to define the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSpec {
    pub provider: CloudProvider,
    pub instance_type: String,
    pub region: String,
}

/// Lifecycle state of an ephemeral compute node.
///
/// Transitions follow: Provisioning → HealthChecking → Active → Destroying → Destroyed.
/// Invalid transitions produce `EphemeralError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeState {
    Provisioning,
    HealthChecking,
    Active,
    Destroying,
    Destroyed,
}

impl fmt::Display for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provisioning => write!(f, "Provisioning"),
            Self::HealthChecking => write!(f, "HealthChecking"),
            Self::Active => write!(f, "Active"),
            Self::Destroying => write!(f, "Destroying"),
            Self::Destroyed => write!(f, "Destroyed"),
        }
    }
}

/// A single ephemeral compute node managed by the executor.
///
/// Contains the node's unique identifier, its specification, current lifecycle
/// state, and an optional IP address assigned after successful provisioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralNode {
    pub id: String,
    pub spec: NodeSpec,
    pub state: NodeState,
    pub ip_address: Option<String>,
}

/// Terraform HCL configuration wrapper produced by the executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformConfig {
    pub spec: NodeSpec,
    pub hcl: String,
}

/// Errors produced by ephemeral infrastructure operations.
///
/// Covers all failure modes in the provisioning → health-check → destroy lifecycle.
#[derive(Debug)]
pub enum EphemeralError {
    ProvisionFailed(String),
    HealthCheckFailed(String),
    NodeNotFound(String),
    CleanupFailed(String),
    DestroyFailed(String),
}

impl fmt::Display for EphemeralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProvisionFailed(msg) => write!(f, "provision failed: {msg}"),
            Self::HealthCheckFailed(msg) => write!(f, "health check failed: {msg}"),
            Self::NodeNotFound(id) => write!(f, "node not found: {id}"),
            Self::CleanupFailed(msg) => write!(f, "cleanup failed: {msg}"),
            Self::DestroyFailed(msg) => write!(f, "destroy failed: {msg}"),
        }
    }
}

impl std::error::Error for EphemeralError {}

/// Manages a fleet of ephemeral compute nodes through their full lifecycle.
///
/// Handles provisioning via simulated Terraform init+apply, health checking,
/// work assignment to active nodes, and teardown with cleanup verification.
/// All nodes must reach `Destroyed` state for `verify_cleanup` to return true.
pub struct EphemeralExecutor {
    nodes: Vec<EphemeralNode>,
}

impl EphemeralExecutor {
    pub fn new(specs: Vec<NodeSpec>) -> Self {
        let nodes = specs
            .into_iter()
            .enumerate()
            .map(|(i, spec)| EphemeralNode {
                id: format!("node-{i}"),
                spec,
                state: NodeState::Provisioning,
                ip_address: None,
            })
            .collect();
        Self { nodes }
    }

    pub async fn provision(&mut self) -> Result<(), EphemeralError> {
        for node in &mut self.nodes {
            if node.state != NodeState::Provisioning {
                return Err(EphemeralError::ProvisionFailed(format!(
                    "node {} in unexpected state {}",
                    node.id, node.state
                )));
            }
            node.ip_address = Some(generate_mock_ip(&node.id));
            node.state = NodeState::HealthChecking;
        }
        Ok(())
    }

    pub async fn health_check(&mut self) -> Result<(), EphemeralError> {
        for node in &mut self.nodes {
            if node.state != NodeState::HealthChecking {
                return Err(EphemeralError::HealthCheckFailed(format!(
                    "node {} in state {}, expected HealthChecking",
                    node.id, node.state
                )));
            }
            if node.ip_address.is_none() {
                return Err(EphemeralError::HealthCheckFailed(format!(
                    "node {} has no IP address",
                    node.id
                )));
            }
            node.state = NodeState::Active;
        }
        Ok(())
    }

    pub fn assign_work(&mut self, node_id: &str) -> Result<&EphemeralNode, EphemeralError> {
        let node = self
            .nodes
            .iter()
            .find(|n| n.id == node_id)
            .ok_or_else(|| EphemeralError::NodeNotFound(node_id.to_string()))?;
        if node.state != NodeState::Active {
            return Err(EphemeralError::NodeNotFound(format!(
                "node {node_id} is {}, not Active",
                node.state
            )));
        }
        Ok(node)
    }

    pub async fn destroy_all(&mut self) -> Result<(), EphemeralError> {
        for node in &mut self.nodes {
            match node.state {
                NodeState::Destroyed => continue,
                NodeState::Active | NodeState::HealthChecking | NodeState::Provisioning => {
                    node.state = NodeState::Destroying;
                }
                NodeState::Destroying => {}
            }
            node.state = NodeState::Destroyed;
            node.ip_address = None;
        }
        Ok(())
    }

    pub fn verify_cleanup(&self) -> bool {
        self.nodes.iter().all(|n| n.state == NodeState::Destroyed)
    }

    pub fn generate_terraform_config(&self, spec: &NodeSpec) -> String {
        match spec.provider {
            CloudProvider::Aws => format!(
                r#"provider "aws" {{
  region = "{region}"
}}

resource "aws_instance" "scan_node" {{
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "{instance_type}"

  tags = {{
    Name        = "ephemeral-scan"
    AutoDestroy = "true"
  }}
}}"#,
                region = spec.region,
                instance_type = spec.instance_type,
            ),
            CloudProvider::DigitalOcean => format!(
                r#"provider "digitalocean" {{}}

resource "digitalocean_droplet" "scan_node" {{
  image  = "ubuntu-22-04-x64"
  name   = "ephemeral-scan"
  region = "{region}"
  size   = "{instance_type}"
}}"#,
                region = spec.region,
                instance_type = spec.instance_type,
            ),
            CloudProvider::Vultr => format!(
                r#"provider "vultr" {{}}

resource "vultr_instance" "scan_node" {{
  plan   = "{instance_type}"
  region = "{region}"
  os_id  = 1743
  label  = "ephemeral-scan"
}}"#,
                region = spec.region,
                instance_type = spec.instance_type,
            ),
        }
    }

    pub fn nodes(&self) -> &[EphemeralNode] {
        &self.nodes
    }
}

fn generate_mock_ip(node_id: &str) -> String {
    let hash: u32 = node_id.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    let a = 10;
    let b = (hash >> 16) as u8;
    let c = (hash >> 8) as u8;
    let d = ((hash & 0xFF) as u8).max(1);
    format!("{a}.{b}.{c}.{d}")
}
