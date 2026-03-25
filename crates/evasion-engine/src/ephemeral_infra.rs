use std::fmt;

use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Cloud provider for ephemeral VM provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EphemeralCloudProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
    Vultr,
}

impl fmt::Display for EphemeralCloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aws => write!(f, "AWS"),
            Self::Gcp => write!(f, "GCP"),
            Self::Azure => write!(f, "Azure"),
            Self::DigitalOcean => write!(f, "DigitalOcean"),
            Self::Vultr => write!(f, "Vultr"),
        }
    }
}

/// Region for VM deployment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CloudRegion {
    pub provider: EphemeralCloudProvider,
    pub region_code: String,
    pub display_name: String,
}

/// VM instance size tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstanceTier {
    Micro,
    Small,
    Medium,
    Large,
}

impl InstanceTier {
    /// Returns estimated hourly cost in USD cents.
    pub fn hourly_cost_cents(&self, provider: EphemeralCloudProvider) -> u32 {
        match (provider, self) {
            (EphemeralCloudProvider::Aws, Self::Micro) => 1,
            (EphemeralCloudProvider::Aws, Self::Small) => 2,
            (EphemeralCloudProvider::Aws, Self::Medium) => 8,
            (EphemeralCloudProvider::Aws, Self::Large) => 17,
            (EphemeralCloudProvider::Gcp, Self::Micro) => 1,
            (EphemeralCloudProvider::Gcp, Self::Small) => 3,
            (EphemeralCloudProvider::Gcp, Self::Medium) => 10,
            (EphemeralCloudProvider::Gcp, Self::Large) => 20,
            (EphemeralCloudProvider::Azure, Self::Micro) => 1,
            (EphemeralCloudProvider::Azure, Self::Small) => 2,
            (EphemeralCloudProvider::Azure, Self::Medium) => 9,
            (EphemeralCloudProvider::Azure, Self::Large) => 18,
            (EphemeralCloudProvider::DigitalOcean, Self::Micro) => 1,
            (EphemeralCloudProvider::DigitalOcean, Self::Small) => 1,
            (EphemeralCloudProvider::DigitalOcean, Self::Medium) => 4,
            (EphemeralCloudProvider::DigitalOcean, Self::Large) => 8,
            (EphemeralCloudProvider::Vultr, Self::Micro) => 0,
            (EphemeralCloudProvider::Vultr, Self::Small) => 1,
            (EphemeralCloudProvider::Vultr, Self::Medium) => 4,
            (EphemeralCloudProvider::Vultr, Self::Large) => 8,
        }
    }

    fn instance_type_str(&self, provider: EphemeralCloudProvider) -> &'static str {
        match (provider, self) {
            (EphemeralCloudProvider::Aws, Self::Micro) => "t3.micro",
            (EphemeralCloudProvider::Aws, Self::Small) => "t3.small",
            (EphemeralCloudProvider::Aws, Self::Medium) => "t3.medium",
            (EphemeralCloudProvider::Aws, Self::Large) => "t3.large",
            (EphemeralCloudProvider::Gcp, Self::Micro) => "e2-micro",
            (EphemeralCloudProvider::Gcp, Self::Small) => "e2-small",
            (EphemeralCloudProvider::Gcp, Self::Medium) => "e2-medium",
            (EphemeralCloudProvider::Gcp, Self::Large) => "e2-standard-2",
            (EphemeralCloudProvider::Azure, Self::Micro) => "Standard_B1s",
            (EphemeralCloudProvider::Azure, Self::Small) => "Standard_B1ms",
            (EphemeralCloudProvider::Azure, Self::Medium) => "Standard_B2s",
            (EphemeralCloudProvider::Azure, Self::Large) => "Standard_B2ms",
            (EphemeralCloudProvider::DigitalOcean, Self::Micro) => "s-1vcpu-512mb-10gb",
            (EphemeralCloudProvider::DigitalOcean, Self::Small) => "s-1vcpu-1gb",
            (EphemeralCloudProvider::DigitalOcean, Self::Medium) => "s-2vcpu-2gb",
            (EphemeralCloudProvider::DigitalOcean, Self::Large) => "s-2vcpu-4gb",
            (EphemeralCloudProvider::Vultr, Self::Micro) => "vc2-1c-0.5gb",
            (EphemeralCloudProvider::Vultr, Self::Small) => "vc2-1c-1gb",
            (EphemeralCloudProvider::Vultr, Self::Medium) => "vc2-1c-2gb",
            (EphemeralCloudProvider::Vultr, Self::Large) => "vc2-2c-4gb",
        }
    }
}

/// Generated Terraform configuration for an ephemeral VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformConfig {
    pub provider: EphemeralCloudProvider,
    pub region: String,
    pub instance_type: String,
    pub hcl_body: String,
    pub estimated_hourly_cost_cents: u32,
}

/// Generated Docker Compose configuration for scan node deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerComposeConfig {
    pub yaml_body: String,
    pub service_count: usize,
    pub network_name: String,
}

/// Generated WireGuard peer configuration for mesh networking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeerConfig {
    pub peer_id: u64,
    pub private_key_placeholder: String,
    pub public_key_placeholder: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub config_body: String,
}

/// Generated DNS configuration for disposable callback domains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub domain: String,
    pub record_type: String,
    pub record_value: String,
    pub ttl: u32,
    pub zone_file_entry: String,
}

/// Post-scan cleanup script that shreds all data and destroys VMs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupScript {
    pub provider: Option<EphemeralCloudProvider>,
    pub script_body: String,
    pub shreds_data: bool,
    pub destroys_vms: bool,
}

/// Rotation schedule entry for infrastructure refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationEntry {
    pub rotation_index: u64,
    pub provider: EphemeralCloudProvider,
    pub region: String,
    pub instance_type: String,
    pub ttl_minutes: u64,
}

/// Cost estimate for a scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEstimate {
    pub vm_count: usize,
    pub estimated_duration_hours: f64,
    pub per_vm_hourly_cents: u32,
    pub total_estimated_cents: u64,
    pub provider: EphemeralCloudProvider,
}

/// Configuration for the ephemeral infrastructure generator.
#[derive(Debug, Clone)]
pub struct EphemeralInfraConfig {
    pub providers: Vec<EphemeralCloudProvider>,
    pub instance_tier: InstanceTier,
    pub node_count: usize,
    pub rotation_interval_minutes: u64,
    pub wireguard_mesh: bool,
    pub dns_callback_domain: Option<String>,
    pub auto_cleanup: bool,
}

impl Default for EphemeralInfraConfig {
    fn default() -> Self {
        Self {
            providers: vec![
                EphemeralCloudProvider::Aws,
                EphemeralCloudProvider::DigitalOcean,
            ],
            instance_tier: InstanceTier::Small,
            node_count: 3,
            rotation_interval_minutes: 30,
            wireguard_mesh: true,
            dns_callback_domain: None,
            auto_cleanup: true,
        }
    }
}

impl EphemeralInfraConfig {
    pub fn with_providers(mut self, providers: Vec<EphemeralCloudProvider>) -> Self {
        self.providers = providers;
        self
    }

    pub fn with_tier(mut self, tier: InstanceTier) -> Self {
        self.instance_tier = tier;
        self
    }

    pub fn with_node_count(mut self, count: usize) -> Self {
        self.node_count = count;
        self
    }

    pub fn with_rotation_interval(mut self, minutes: u64) -> Self {
        self.rotation_interval_minutes = minutes;
        self
    }

    pub fn with_dns_domain(mut self, domain: &str) -> Self {
        self.dns_callback_domain = Some(domain.to_string());
        self
    }
}

/// Default regions per provider.
fn default_region(provider: EphemeralCloudProvider) -> &'static str {
    match provider {
        EphemeralCloudProvider::Aws => "eu-west-1",
        EphemeralCloudProvider::Gcp => "europe-west1",
        EphemeralCloudProvider::Azure => "westeurope",
        EphemeralCloudProvider::DigitalOcean => "ams3",
        EphemeralCloudProvider::Vultr => "ams",
    }
}

/// Ephemeral infrastructure generator that produces configs for disposable
/// scanning infrastructure across multiple cloud providers with mesh networking,
/// DNS callback domains, cleanup scripts, and rotation schedules.
pub struct EphemeralInfraGenerator {
    config: EphemeralInfraConfig,
    _rng: StdRng,
    next_peer_id: u64,
    generated_configs: Vec<TerraformConfig>,
    rotation_index: u64,
}

impl EphemeralInfraGenerator {
    pub fn new(config: EphemeralInfraConfig) -> Self {
        Self {
            config,
            _rng: StdRng::from_os_rng(),
            next_peer_id: 1,
            generated_configs: Vec::new(),
            rotation_index: 0,
        }
    }

    pub fn with_seed(config: EphemeralInfraConfig, seed: u64) -> Self {
        Self {
            config,
            _rng: StdRng::seed_from_u64(seed),
            next_peer_id: 1,
            generated_configs: Vec::new(),
            rotation_index: 0,
        }
    }

    /// Generates a Terraform HCL config for a single ephemeral VM.
    pub fn generate_terraform(&mut self, provider: EphemeralCloudProvider) -> TerraformConfig {
        let region = default_region(provider).to_string();
        let instance_type = self
            .config
            .instance_tier
            .instance_type_str(provider)
            .to_string();
        let cost = self.config.instance_tier.hourly_cost_cents(provider);

        let hcl = match provider {
            EphemeralCloudProvider::Aws => format!(
                r#"provider "aws" {{
  region = "{region}"
}}

resource "aws_instance" "scan_node" {{
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "{instance_type}"

  tags = {{
    Name        = "ephemeral-scan-{rotation}"
    AutoDestroy = "true"
  }}

  provisioner "remote-exec" {{
    inline = ["sudo apt-get update && sudo apt-get install -y wireguard"]
  }}
}}

resource "aws_security_group" "scan_sg" {{
  ingress {{
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}"#,
                rotation = self.rotation_index,
            ),
            EphemeralCloudProvider::Gcp => format!(
                r#"provider "google" {{
  project = "ephemeral-scan"
  region  = "{region}"
}}

resource "google_compute_instance" "scan_node" {{
  name         = "scan-node-{rotation}"
  machine_type = "{instance_type}"
  zone         = "{region}-b"

  boot_disk {{
    initialize_params {{
      image = "debian-cloud/debian-11"
    }}
  }}

  network_interface {{
    network = "default"
    access_config {{}}
  }}

  metadata_startup_script = "apt-get update && apt-get install -y wireguard"
}}"#,
                rotation = self.rotation_index,
            ),
            EphemeralCloudProvider::Azure => format!(
                r#"provider "azurerm" {{
  features {{}}
}}

resource "azurerm_linux_virtual_machine" "scan_node" {{
  name                = "scan-node-{rotation}"
  resource_group_name = "ephemeral-scans"
  location            = "{region}"
  size                = "{instance_type}"
  admin_username      = "scanuser"

  os_disk {{
    caching              = "None"
    storage_account_type = "Standard_LRS"
  }}

  source_image_reference {{
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }}
}}"#,
                rotation = self.rotation_index,
            ),
            EphemeralCloudProvider::DigitalOcean => format!(
                r#"provider "digitalocean" {{}}

resource "digitalocean_droplet" "scan_node" {{
  image    = "ubuntu-22-04-x64"
  name     = "scan-node-{rotation}"
  region   = "{region}"
  size     = "{instance_type}"

  user_data = <<-EOF
    #!/bin/bash
    apt-get update && apt-get install -y wireguard
  EOF
}}"#,
                rotation = self.rotation_index,
            ),
            EphemeralCloudProvider::Vultr => format!(
                r#"provider "vultr" {{}}

resource "vultr_instance" "scan_node" {{
  plan     = "{instance_type}"
  region   = "{region}"
  os_id    = 1743
  label    = "scan-node-{rotation}"
  hostname = "scan-{rotation}"
}}"#,
                rotation = self.rotation_index,
            ),
        };

        let tf = TerraformConfig {
            provider,
            region,
            instance_type,
            hcl_body: hcl,
            estimated_hourly_cost_cents: cost,
        };
        self.generated_configs.push(tf.clone());
        tf
    }

    /// Generates a Docker Compose config for deploying scan nodes.
    pub fn generate_docker_compose(&self, node_count: usize) -> DockerComposeConfig {
        let network_name = "scan-mesh";
        let mut services = String::new();
        for i in 0..node_count {
            services.push_str(&format!(
                r#"  scan-node-{i}:
    image: alpine:3.18
    container_name: scan-node-{i}
    networks:
      - {network_name}
    cap_add:
      - NET_ADMIN
    sysctls:
      - net.ipv4.ip_forward=1
    volumes:
      - /dev/null:/dev/null
    command: ["sleep", "infinity"]
    restart: "no"
"#,
            ));
        }

        let yaml = format!(
            r#"version: "3.8"

services:
{services}
networks:
  {network_name}:
    driver: bridge
    ipam:
      config:
        - subnet: 10.99.0.0/24
"#,
        );

        DockerComposeConfig {
            yaml_body: yaml,
            service_count: node_count,
            network_name: network_name.to_string(),
        }
    }

    /// Generates WireGuard peer configs for mesh networking between nodes.
    pub fn generate_wireguard_mesh(&mut self, endpoints: &[&str]) -> Vec<WireGuardPeerConfig> {
        let mut peers = Vec::new();
        let base_subnet = "10.200.200";

        for (i, endpoint) in endpoints.iter().enumerate() {
            let peer_id = self.next_peer_id;
            self.next_peer_id += 1;
            let ip_octet = i + 1;
            let address = format!("{base_subnet}.{ip_octet}/24");

            let mut peer_entries = String::new();
            for (j, other_ep) in endpoints.iter().enumerate() {
                if j == i {
                    continue;
                }
                let other_octet = j + 1;
                peer_entries.push_str(&format!(
                    "\n[Peer]\nPublicKey = PEER_{j}_PUBLIC_KEY_PLACEHOLDER\nEndpoint = {other_ep}:51820\nAllowedIPs = {base_subnet}.{other_octet}/32\nPersistentKeepalive = 25\n"
                ));
            }

            let config_body = format!(
                "[Interface]\nPrivateKey = PEER_{i}_PRIVATE_KEY_PLACEHOLDER\nAddress = {address}\nListenPort = 51820\n{peer_entries}"
            );

            peers.push(WireGuardPeerConfig {
                peer_id,
                private_key_placeholder: format!("PEER_{i}_PRIVATE_KEY_PLACEHOLDER"),
                public_key_placeholder: format!("PEER_{i}_PUBLIC_KEY_PLACEHOLDER"),
                endpoint: endpoint.to_string(),
                allowed_ips: address,
                config_body,
            });
        }

        peers
    }

    /// Generates DNS records for disposable callback/C2 domains.
    pub fn generate_dns_config(&self, subdomains: &[&str]) -> Vec<DnsConfig> {
        let base_domain = self
            .config
            .dns_callback_domain
            .as_deref()
            .unwrap_or("callback.example.com");

        subdomains
            .iter()
            .map(|sub| {
                let fqdn = format!("{sub}.{base_domain}");
                let zone_entry = format!("{sub}    IN    A    127.0.0.1");
                DnsConfig {
                    domain: fqdn,
                    record_type: "A".to_string(),
                    record_value: "127.0.0.1".to_string(),
                    ttl: 60,
                    zone_file_entry: zone_entry,
                }
            })
            .collect()
    }

    /// Generates a cleanup script that shreds all data and destroys VMs.
    pub fn generate_cleanup_script(
        &self,
        provider: Option<EphemeralCloudProvider>,
    ) -> CleanupScript {
        let base_cleanup = r#"#!/bin/bash
set -euo pipefail

echo "[*] Shredding scan data..."
find /tmp/aegis-scan -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
rm -rf /tmp/aegis-scan

echo "[*] Clearing shell history..."
cat /dev/null > ~/.bash_history
history -c

echo "[*] Flushing logs..."
journalctl --rotate --vacuum-time=1s 2>/dev/null || true

echo "[*] Clearing DNS cache..."
resolvectl flush-caches 2>/dev/null || true

echo "[*] Wiping temporary files..."
shred -vfz -n 3 /tmp/.aegis-* 2>/dev/null || true

echo "[*] Dropping WireGuard interfaces..."
wg-quick down wg0 2>/dev/null || true
rm -f /etc/wireguard/wg0.conf
"#;

        let provider_cleanup = match provider {
            Some(EphemeralCloudProvider::Aws) => {
                "\necho \"[*] Self-terminating AWS instance...\"\nINSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)\naws ec2 terminate-instances --instance-ids $INSTANCE_ID\n"
            }
            Some(EphemeralCloudProvider::Gcp) => {
                "\necho \"[*] Self-deleting GCP instance...\"\nNAME=$(curl -sH 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/name)\nZONE=$(curl -sH 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/zone)\ngcloud compute instances delete $NAME --zone=$ZONE --quiet\n"
            }
            Some(EphemeralCloudProvider::DigitalOcean) => {
                "\necho \"[*] Self-destroying DigitalOcean droplet...\"\nDROPLET_ID=$(curl -s http://169.254.169.254/metadata/v1/id)\ncurl -X DELETE \"https://api.digitalocean.com/v2/droplets/$DROPLET_ID\" -H \"Authorization: Bearer $DO_TOKEN\"\n"
            }
            _ => "",
        };

        CleanupScript {
            provider,
            script_body: format!("{base_cleanup}{provider_cleanup}"),
            shreds_data: true,
            destroys_vms: provider.is_some(),
        }
    }

    /// Generates a rotation schedule for cycling infrastructure.
    pub fn generate_rotation_schedule(&mut self, count: usize) -> Vec<RotationEntry> {
        let mut entries = Vec::new();
        let providers = &self.config.providers;
        let interval = self.config.rotation_interval_minutes;

        for i in 0..count {
            let provider = providers[i % providers.len()];
            let region = default_region(provider).to_string();
            let instance_type = self
                .config
                .instance_tier
                .instance_type_str(provider)
                .to_string();

            entries.push(RotationEntry {
                rotation_index: self.rotation_index,
                provider,
                region,
                instance_type,
                ttl_minutes: interval,
            });
            self.rotation_index += 1;
        }

        entries
    }

    /// Estimates the total cost for a scan run.
    pub fn estimate_cost(
        &self,
        provider: EphemeralCloudProvider,
        vm_count: usize,
        duration_hours: f64,
    ) -> CostEstimate {
        let per_vm = self.config.instance_tier.hourly_cost_cents(provider);
        let total = (vm_count as f64 * duration_hours * per_vm as f64).ceil() as u64;

        CostEstimate {
            vm_count,
            estimated_duration_hours: duration_hours,
            per_vm_hourly_cents: per_vm,
            total_estimated_cents: total,
            provider,
        }
    }

    /// Returns the number of generated Terraform configs so far.
    pub fn generated_count(&self) -> usize {
        self.generated_configs.len()
    }

    /// Returns the current rotation index.
    pub fn rotation_index(&self) -> u64 {
        self.rotation_index
    }
}
