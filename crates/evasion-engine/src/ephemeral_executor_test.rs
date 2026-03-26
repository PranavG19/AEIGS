#[cfg(test)]
mod tests {
    use crate::ephemeral_executor::{
        CloudProvider, EphemeralExecutor, EphemeralError, NodeSpec, NodeState,
    };

    fn aws_spec() -> NodeSpec {
        NodeSpec {
            provider: CloudProvider::Aws,
            instance_type: "t3.micro".to_string(),
            region: "us-east-1".to_string(),
        }
    }

    fn do_spec() -> NodeSpec {
        NodeSpec {
            provider: CloudProvider::DigitalOcean,
            instance_type: "s-1vcpu-1gb".to_string(),
            region: "nyc1".to_string(),
        }
    }

    fn vultr_spec() -> NodeSpec {
        NodeSpec {
            provider: CloudProvider::Vultr,
            instance_type: "vc2-1c-1gb".to_string(),
            region: "ewr".to_string(),
        }
    }

    #[tokio::test]
    async fn test_provision_lifecycle() {
        let mut executor = EphemeralExecutor::new(vec![aws_spec(), do_spec()]);
        assert!(executor.nodes().iter().all(|n| n.state == NodeState::Provisioning));

        executor.provision().await.unwrap();
        assert!(executor.nodes().iter().all(|n| n.state == NodeState::HealthChecking));
        assert!(executor.nodes().iter().all(|n| n.ip_address.is_some()));

        executor.health_check().await.unwrap();
        assert!(executor.nodes().iter().all(|n| n.state == NodeState::Active));

        let node = executor.assign_work("node-0").unwrap();
        assert_eq!(node.state, NodeState::Active);
        assert!(node.ip_address.is_some());

        executor.destroy_all().await.unwrap();
        assert!(executor.nodes().iter().all(|n| n.state == NodeState::Destroyed));
        assert!(executor.nodes().iter().all(|n| n.ip_address.is_none()));
    }

    #[tokio::test]
    async fn test_cleanup_verification() {
        let mut executor = EphemeralExecutor::new(vec![aws_spec()]);
        assert!(!executor.verify_cleanup());

        executor.provision().await.unwrap();
        assert!(!executor.verify_cleanup());

        executor.health_check().await.unwrap();
        assert!(!executor.verify_cleanup());

        executor.destroy_all().await.unwrap();
        assert!(executor.verify_cleanup());
    }

    #[tokio::test]
    async fn test_multi_provider() {
        let specs = vec![aws_spec(), do_spec(), vultr_spec()];
        let mut executor = EphemeralExecutor::new(specs);

        executor.provision().await.unwrap();
        executor.health_check().await.unwrap();

        assert_eq!(executor.nodes().len(), 3);
        assert_eq!(executor.nodes()[0].spec.provider, CloudProvider::Aws);
        assert_eq!(executor.nodes()[1].spec.provider, CloudProvider::DigitalOcean);
        assert_eq!(executor.nodes()[2].spec.provider, CloudProvider::Vultr);

        for node in executor.nodes() {
            assert_eq!(node.state, NodeState::Active);
            assert!(node.ip_address.is_some());
        }

        executor.destroy_all().await.unwrap();
        assert!(executor.verify_cleanup());
    }

    #[test]
    fn test_terraform_config_generation() {
        let executor = EphemeralExecutor::new(vec![]);

        let aws_hcl = executor.generate_terraform_config(&aws_spec());
        assert!(aws_hcl.contains("provider \"aws\""));
        assert!(aws_hcl.contains("us-east-1"));
        assert!(aws_hcl.contains("t3.micro"));
        assert!(aws_hcl.contains("aws_instance"));

        let do_hcl = executor.generate_terraform_config(&do_spec());
        assert!(do_hcl.contains("provider \"digitalocean\""));
        assert!(do_hcl.contains("nyc1"));
        assert!(do_hcl.contains("s-1vcpu-1gb"));
        assert!(do_hcl.contains("digitalocean_droplet"));

        let vultr_hcl = executor.generate_terraform_config(&vultr_spec());
        assert!(vultr_hcl.contains("provider \"vultr\""));
        assert!(vultr_hcl.contains("ewr"));
        assert!(vultr_hcl.contains("vc2-1c-1gb"));
        assert!(vultr_hcl.contains("vultr_instance"));
    }

    #[tokio::test]
    async fn test_state_machine_transitions() {
        let mut executor = EphemeralExecutor::new(vec![aws_spec()]);
        assert_eq!(executor.nodes()[0].state, NodeState::Provisioning);

        executor.provision().await.unwrap();
        assert_eq!(executor.nodes()[0].state, NodeState::HealthChecking);

        executor.health_check().await.unwrap();
        assert_eq!(executor.nodes()[0].state, NodeState::Active);

        executor.destroy_all().await.unwrap();
        assert_eq!(executor.nodes()[0].state, NodeState::Destroyed);
    }

    #[tokio::test]
    async fn test_assign_nonexistent_node() {
        let mut executor = EphemeralExecutor::new(vec![aws_spec()]);
        executor.provision().await.unwrap();
        executor.health_check().await.unwrap();
        let result = executor.assign_work("node-999");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_assign_non_active_node() {
        let mut executor = EphemeralExecutor::new(vec![aws_spec()]);
        executor.provision().await.unwrap();
        let result = executor.assign_work("node-0");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_double_destroy_is_safe() {
        let mut executor = EphemeralExecutor::new(vec![aws_spec()]);
        executor.provision().await.unwrap();
        executor.health_check().await.unwrap();
        executor.destroy_all().await.unwrap();
        executor.destroy_all().await.unwrap();
        assert!(executor.verify_cleanup());
    }

    #[test]
    fn test_cloud_provider_display() {
        assert_eq!(CloudProvider::Aws.to_string(), "AWS");
        assert_eq!(CloudProvider::DigitalOcean.to_string(), "DigitalOcean");
        assert_eq!(CloudProvider::Vultr.to_string(), "Vultr");
    }

    #[test]
    fn test_node_state_display() {
        assert_eq!(NodeState::Provisioning.to_string(), "Provisioning");
        assert_eq!(NodeState::HealthChecking.to_string(), "HealthChecking");
        assert_eq!(NodeState::Active.to_string(), "Active");
        assert_eq!(NodeState::Destroying.to_string(), "Destroying");
        assert_eq!(NodeState::Destroyed.to_string(), "Destroyed");
    }

    #[test]
    fn test_ephemeral_error_display() {
        let err = EphemeralError::ProvisionFailed("timeout".to_string());
        assert!(err.to_string().contains("provision failed"));
        assert!(err.to_string().contains("timeout"));

        let err = EphemeralError::NodeNotFound("node-42".to_string());
        assert!(err.to_string().contains("node not found"));
    }

    #[tokio::test]
    async fn test_provision_assigns_unique_ips() {
        let mut executor = EphemeralExecutor::new(vec![aws_spec(), do_spec(), vultr_spec()]);
        executor.provision().await.unwrap();
        let ips: Vec<String> = executor
            .nodes()
            .iter()
            .filter_map(|n| n.ip_address.clone())
            .collect();
        assert_eq!(ips.len(), 3);
        let unique: std::collections::HashSet<&String> = ips.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn test_empty_executor() {
        let executor = EphemeralExecutor::new(vec![]);
        assert!(executor.verify_cleanup());
        assert!(executor.nodes().is_empty());
    }

    #[test]
    fn test_node_ids_sequential() {
        let executor = EphemeralExecutor::new(vec![aws_spec(), do_spec(), vultr_spec()]);
        assert_eq!(executor.nodes()[0].id, "node-0");
        assert_eq!(executor.nodes()[1].id, "node-1");
        assert_eq!(executor.nodes()[2].id, "node-2");
    }
}
