#[cfg(test)]
mod tests {
    use crate::mutator::{MutationStrategy, PayloadMutator};
    use crate::scheduler::VulnerabilityClassTarget;

    #[test]
    fn generate_sqli_payloads() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_payloads(VulnerabilityClassTarget::SqlInjection, 5);
        assert_eq!(payloads.len(), 5);
        for p in &payloads {
            assert_eq!(
                p.vulnerability_class,
                VulnerabilityClassTarget::SqlInjection
            );
            assert!(!p.raw.is_empty());
        }
    }

    #[test]
    fn generate_xss_payloads() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_payloads(VulnerabilityClassTarget::CrossSiteScripting, 3);
        assert_eq!(payloads.len(), 3);
        assert!(payloads[0].raw.contains("script") || payloads[0].raw.contains("alert"));
    }

    #[test]
    fn generate_more_than_templates_uses_bitflip() {
        let mutator = PayloadMutator::new();
        let template_count = mutator.template_count(VulnerabilityClassTarget::CrlfInjection);
        let payloads =
            mutator.generate_payloads(VulnerabilityClassTarget::CrlfInjection, template_count + 5);
        assert_eq!(payloads.len(), template_count + 5);

        let bitflip_count = payloads
            .iter()
            .filter(|p| p.mutation_strategy == MutationStrategy::BitFlip)
            .count();
        assert_eq!(bitflip_count, 5);
    }

    #[test]
    fn boundary_payloads_generated() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_boundary_payloads();
        assert!(payloads.len() >= 10);
        assert!(payloads.iter().any(|p| p.raw.is_empty()));
        assert!(payloads.iter().any(|p| p.raw == "null"));
        assert!(
            payloads
                .iter()
                .any(|p| p.mutation_strategy == MutationStrategy::Boundary)
        );
    }

    #[test]
    fn template_count_for_each_class() {
        let mutator = PayloadMutator::new();
        assert!(mutator.template_count(VulnerabilityClassTarget::SqlInjection) > 0);
        assert!(mutator.template_count(VulnerabilityClassTarget::CrossSiteScripting) > 0);
        assert!(mutator.template_count(VulnerabilityClassTarget::CommandInjection) > 0);
        assert!(mutator.template_count(VulnerabilityClassTarget::PathTraversal) > 0);
        assert!(mutator.template_count(VulnerabilityClassTarget::ServerSideRequestForgery) > 0);
        assert!(mutator.template_count(VulnerabilityClassTarget::ServerSideTemplateInjection) > 0);
    }

    #[test]
    fn mutation_strategy_display() {
        assert_eq!(MutationStrategy::Template.to_string(), "template");
        assert_eq!(MutationStrategy::Generative.to_string(), "generative");
        assert_eq!(MutationStrategy::BitFlip.to_string(), "bitflip");
        assert_eq!(MutationStrategy::Boundary.to_string(), "boundary");
    }

    #[test]
    fn default_creates_mutator_with_templates() {
        let mutator = PayloadMutator::default();
        assert!(mutator.template_count(VulnerabilityClassTarget::SqlInjection) > 0);
    }

    #[test]
    fn payloads_are_non_empty() {
        let mutator = PayloadMutator::new();
        let all_classes = vec![
            VulnerabilityClassTarget::SqlInjection,
            VulnerabilityClassTarget::CrossSiteScripting,
            VulnerabilityClassTarget::CommandInjection,
            VulnerabilityClassTarget::PathTraversal,
            VulnerabilityClassTarget::ServerSideRequestForgery,
            VulnerabilityClassTarget::ServerSideTemplateInjection,
            VulnerabilityClassTarget::Deserialization,
            VulnerabilityClassTarget::HeaderInjection,
            VulnerabilityClassTarget::OpenRedirect,
            VulnerabilityClassTarget::CrlfInjection,
        ];

        for class in all_classes {
            let payloads = mutator.generate_payloads(class, 2);
            for p in payloads {
                assert!(!p.raw.is_empty(), "empty payload for {class}");
            }
        }
    }
}
