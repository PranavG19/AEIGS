use super::ephemeral_infra::*;

fn make_generator() -> EphemeralInfraGenerator {
    EphemeralInfraGenerator::with_seed(EphemeralInfraConfig::default(), 42)
}

#[test]
fn generate_terraform_aws() {
    let mut gen = make_generator();
    let tf = gen.generate_terraform(EphemeralCloudProvider::Aws);
    assert_eq!(tf.provider, EphemeralCloudProvider::Aws);
    assert!(tf.hcl_body.contains("aws_instance"));
    assert!(tf.hcl_body.contains("t3.small"));
    assert!(tf.region.contains("eu-west"));
    assert!(tf.estimated_hourly_cost_cents > 0);
}

#[test]
fn generate_terraform_gcp() {
    let mut gen = make_generator();
    let tf = gen.generate_terraform(EphemeralCloudProvider::Gcp);
    assert!(tf.hcl_body.contains("google_compute_instance"));
    assert!(tf.hcl_body.contains("e2-small"));
}

#[test]
fn generate_terraform_azure() {
    let mut gen = make_generator();
    let tf = gen.generate_terraform(EphemeralCloudProvider::Azure);
    assert!(tf.hcl_body.contains("azurerm_linux_virtual_machine"));
    assert!(tf.hcl_body.contains("Standard_B1ms"));
}

#[test]
fn generate_terraform_digitalocean() {
    let mut gen = make_generator();
    let tf = gen.generate_terraform(EphemeralCloudProvider::DigitalOcean);
    assert!(tf.hcl_body.contains("digitalocean_droplet"));
    assert!(tf.region.contains("ams"));
}

#[test]
fn generate_terraform_vultr() {
    let mut gen = make_generator();
    let tf = gen.generate_terraform(EphemeralCloudProvider::Vultr);
    assert!(tf.hcl_body.contains("vultr_instance"));
}

#[test]
fn generated_count_increments() {
    let mut gen = make_generator();
    assert_eq!(gen.generated_count(), 0);
    gen.generate_terraform(EphemeralCloudProvider::Aws);
    assert_eq!(gen.generated_count(), 1);
    gen.generate_terraform(EphemeralCloudProvider::Gcp);
    assert_eq!(gen.generated_count(), 2);
}

#[test]
fn generate_docker_compose_creates_services() {
    let gen = make_generator();
    let dc = gen.generate_docker_compose(3);
    assert_eq!(dc.service_count, 3);
    assert!(dc.yaml_body.contains("scan-node-0"));
    assert!(dc.yaml_body.contains("scan-node-1"));
    assert!(dc.yaml_body.contains("scan-node-2"));
    assert!(dc.yaml_body.contains("scan-mesh"));
    assert!(dc.yaml_body.contains("NET_ADMIN"));
}

#[test]
fn generate_wireguard_mesh_creates_peers() {
    let mut gen = make_generator();
    let endpoints = vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"];
    let peers = gen.generate_wireguard_mesh(&endpoints);
    assert_eq!(peers.len(), 3);
    assert!(peers[0].config_body.contains("[Interface]"));
    assert!(peers[0].config_body.contains("10.200.200.1/24"));
    assert!(peers[1].config_body.contains("10.200.200.2/24"));
    assert!(peers[0].config_body.contains("[Peer]"));
}

#[test]
fn wireguard_mesh_peers_reference_each_other() {
    let mut gen = make_generator();
    let endpoints = vec!["10.0.0.1", "10.0.0.2"];
    let peers = gen.generate_wireguard_mesh(&endpoints);
    assert!(peers[0]
        .config_body
        .contains("PEER_1_PUBLIC_KEY_PLACEHOLDER"));
    assert!(peers[1]
        .config_body
        .contains("PEER_0_PUBLIC_KEY_PLACEHOLDER"));
}

#[test]
fn generate_dns_config_with_custom_domain() {
    let gen = EphemeralInfraGenerator::with_seed(
        EphemeralInfraConfig::default().with_dns_domain("cb.scanner.io"),
        42,
    );
    let records = gen.generate_dns_config(&["oast", "exfil", "c2"]);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].domain, "oast.cb.scanner.io");
    assert_eq!(records[1].domain, "exfil.cb.scanner.io");
    assert_eq!(records[0].record_type, "A");
    assert_eq!(records[0].ttl, 60);
}

#[test]
fn generate_dns_config_default_domain() {
    let gen = make_generator();
    let records = gen.generate_dns_config(&["test"]);
    assert!(records[0].domain.contains("callback.example.com"));
}

#[test]
fn generate_cleanup_script_shreds_data() {
    let gen = make_generator();
    let script = gen.generate_cleanup_script(None);
    assert!(script.shreds_data);
    assert!(!script.destroys_vms);
    assert!(script.script_body.contains("shred"));
    assert!(script.script_body.contains("history"));
}

#[test]
fn cleanup_script_aws_self_terminates() {
    let gen = make_generator();
    let script = gen.generate_cleanup_script(Some(EphemeralCloudProvider::Aws));
    assert!(script.destroys_vms);
    assert!(script.script_body.contains("terminate-instances"));
}

#[test]
fn cleanup_script_gcp_self_deletes() {
    let gen = make_generator();
    let script = gen.generate_cleanup_script(Some(EphemeralCloudProvider::Gcp));
    assert!(script
        .script_body
        .contains("gcloud compute instances delete"));
}

#[test]
fn cleanup_script_digitalocean_self_destroys() {
    let gen = make_generator();
    let script = gen.generate_cleanup_script(Some(EphemeralCloudProvider::DigitalOcean));
    assert!(script.script_body.contains("DELETE"));
    assert!(script.script_body.contains("droplets"));
}

#[test]
fn generate_rotation_schedule() {
    let mut gen = make_generator();
    let schedule = gen.generate_rotation_schedule(4);
    assert_eq!(schedule.len(), 4);
    assert_eq!(schedule[0].provider, EphemeralCloudProvider::Aws);
    assert_eq!(schedule[1].provider, EphemeralCloudProvider::DigitalOcean);
    assert_eq!(schedule[2].provider, EphemeralCloudProvider::Aws);
    assert_eq!(schedule[0].ttl_minutes, 30);
}

#[test]
fn rotation_index_increments() {
    let mut gen = make_generator();
    assert_eq!(gen.rotation_index(), 0);
    gen.generate_rotation_schedule(3);
    assert_eq!(gen.rotation_index(), 3);
}

#[test]
fn estimate_cost_calculates_correctly() {
    let gen = make_generator();
    let est = gen.estimate_cost(EphemeralCloudProvider::Aws, 5, 2.0);
    assert_eq!(est.vm_count, 5);
    assert_eq!(est.provider, EphemeralCloudProvider::Aws);
    assert_eq!(est.per_vm_hourly_cents, 2);
    assert_eq!(est.total_estimated_cents, 20);
}

#[test]
fn estimate_cost_different_tiers() {
    let gen = EphemeralInfraGenerator::with_seed(
        EphemeralInfraConfig::default().with_tier(InstanceTier::Large),
        42,
    );
    let est = gen.estimate_cost(EphemeralCloudProvider::Aws, 1, 1.0);
    assert_eq!(est.per_vm_hourly_cents, 17);
}

#[test]
fn cloud_provider_display() {
    assert_eq!(format!("{}", EphemeralCloudProvider::Aws), "AWS");
    assert_eq!(format!("{}", EphemeralCloudProvider::Gcp), "GCP");
    assert_eq!(format!("{}", EphemeralCloudProvider::Azure), "Azure");
    assert_eq!(format!("{}", EphemeralCloudProvider::DigitalOcean), "DigitalOcean");
    assert_eq!(format!("{}", EphemeralCloudProvider::Vultr), "Vultr");
}

#[test]
fn config_builder_pattern() {
    let config = EphemeralInfraConfig::default()
        .with_providers(vec![EphemeralCloudProvider::Vultr])
        .with_tier(InstanceTier::Medium)
        .with_node_count(5)
        .with_rotation_interval(15)
        .with_dns_domain("test.example.com");
    assert_eq!(config.providers, vec![EphemeralCloudProvider::Vultr]);
    assert_eq!(config.instance_tier, InstanceTier::Medium);
    assert_eq!(config.node_count, 5);
    assert_eq!(config.rotation_interval_minutes, 15);
    assert_eq!(
        config.dns_callback_domain.as_deref(),
        Some("test.example.com")
    );
}

#[test]
fn instance_tier_costs_vary_by_provider() {
    let micro_aws = InstanceTier::Micro.hourly_cost_cents(EphemeralCloudProvider::Aws);
    let large_aws = InstanceTier::Large.hourly_cost_cents(EphemeralCloudProvider::Aws);
    assert!(large_aws > micro_aws);
}
