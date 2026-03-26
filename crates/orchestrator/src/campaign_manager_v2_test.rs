#[cfg(test)]
mod tests {
    use crate::campaign_manager_v2::*;

    fn cid(s: &str) -> CampaignId {
        CampaignId(s.to_string())
    }

    #[test]
    fn test_campaign_lifecycle_planning_to_completed() {
        let mut mgr = CampaignManagerV2::new();
        let campaign = mgr.create_campaign(cid("c1"), "Test Campaign".to_string(), 3);
        campaign.add_target(CampaignTarget::new(
            "t1".to_string(),
            "https://a.local".to_string(),
            1,
        ));
        campaign.add_target(CampaignTarget::new(
            "t2".to_string(),
            "https://b.local".to_string(),
            2,
        ));
        assert_eq!(campaign.state, CampaignState::Planning);
        campaign.start().unwrap();
        assert_eq!(campaign.state, CampaignState::Active);
        campaign.advance_target("t1", TargetProgress::Done).unwrap();
        campaign.advance_target("t2", TargetProgress::Done).unwrap();
        assert_eq!(campaign.state, CampaignState::Completed);
    }

    #[test]
    fn test_pause_resume() {
        let mut campaign = Campaign::new(cid("c1"), "Test".to_string(), 2);
        campaign.add_target(CampaignTarget::new(
            "t1".to_string(),
            "https://a.local".to_string(),
            1,
        ));
        campaign.start().unwrap();
        campaign.pause().unwrap();
        assert_eq!(campaign.state, CampaignState::Paused);
        assert!(campaign.paused_at.is_some());
        campaign.resume().unwrap();
        assert_eq!(campaign.state, CampaignState::Active);
    }

    #[test]
    fn test_cannot_start_active_campaign() {
        let mut campaign = Campaign::new(cid("c1"), "Test".to_string(), 2);
        campaign.start().unwrap();
        assert!(campaign.start().is_err());
    }

    #[test]
    fn test_abort() {
        let mut campaign = Campaign::new(cid("c1"), "Test".to_string(), 2);
        campaign.start().unwrap();
        campaign.abort();
        assert_eq!(campaign.state, CampaignState::Aborted);
        assert!(campaign.completed_at.is_some());
    }

    #[test]
    fn test_dependency_management() {
        let mut campaign = Campaign::new(cid("c1"), "Test".to_string(), 5);
        let t1 = CampaignTarget::new("recon".to_string(), "https://a.local".to_string(), 1);
        let t2 = CampaignTarget::new("fuzz".to_string(), "https://a.local/api".to_string(), 2)
            .with_dependency("recon".to_string());
        let t3 = CampaignTarget::new("exploit".to_string(), "https://a.local/api".to_string(), 3)
            .with_dependency("fuzz".to_string());
        campaign.add_target(t1);
        campaign.add_target(t2);
        campaign.add_target(t3);
        campaign.start().unwrap();
        let ready = campaign.ready_targets();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].target_id, "recon");
        campaign
            .advance_target("recon", TargetProgress::Done)
            .unwrap();
        let ready = campaign.ready_targets();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].target_id, "fuzz");
    }

    #[test]
    fn test_max_concurrent_limit() {
        let mut campaign = Campaign::new(cid("c1"), "Test".to_string(), 2);
        for i in 0..5 {
            campaign.add_target(CampaignTarget::new(
                format!("t{}", i),
                format!("https://{}.local", i),
                1,
            ));
        }
        campaign.start().unwrap();
        let ready = campaign.ready_targets();
        assert_eq!(ready.len(), 2);
        campaign
            .advance_target("t0", TargetProgress::Recon)
            .unwrap();
        campaign
            .advance_target("t1", TargetProgress::Recon)
            .unwrap();
        let ready = campaign.ready_targets();
        assert_eq!(ready.len(), 0);
        campaign.advance_target("t0", TargetProgress::Done).unwrap();
        let ready = campaign.ready_targets();
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn test_target_progress_tracking() {
        let mut campaign = Campaign::new(cid("c1"), "Test".to_string(), 5);
        campaign.add_target(CampaignTarget::new(
            "t1".to_string(),
            "https://a.local".to_string(),
            1,
        ));
        campaign.start().unwrap();
        campaign
            .advance_target("t1", TargetProgress::Recon)
            .unwrap();
        let t = campaign
            .targets
            .iter()
            .find(|t| t.target_id == "t1")
            .unwrap();
        assert!(t.started_at.is_some());
        assert!(t.completed_at.is_none());
        campaign.advance_target("t1", TargetProgress::Done).unwrap();
        let t = campaign
            .targets
            .iter()
            .find(|t| t.target_id == "t1")
            .unwrap();
        assert!(t.completed_at.is_some());
    }

    #[test]
    fn test_record_findings() {
        let mut campaign = Campaign::new(cid("c1"), "Test".to_string(), 5);
        campaign.add_target(CampaignTarget::new(
            "t1".to_string(),
            "https://a.local".to_string(),
            1,
        ));
        campaign.record_finding("t1").unwrap();
        campaign.record_finding("t1").unwrap();
        let t = campaign
            .targets
            .iter()
            .find(|t| t.target_id == "t1")
            .unwrap();
        assert_eq!(t.findings_count, 2);
        assert!(campaign.record_finding("nonexistent").is_err());
    }

    #[test]
    fn test_campaign_stats() {
        let mut campaign = Campaign::new(cid("c1"), "Test".to_string(), 5);
        campaign.add_target(CampaignTarget::new(
            "t1".to_string(),
            "https://a.local".to_string(),
            1,
        ));
        campaign.add_target(CampaignTarget::new(
            "t2".to_string(),
            "https://b.local".to_string(),
            1,
        ));
        campaign.add_target(CampaignTarget::new(
            "t3".to_string(),
            "https://c.local".to_string(),
            1,
        ));
        campaign.record_finding("t1").unwrap();
        campaign.advance_target("t1", TargetProgress::Done).unwrap();
        campaign
            .advance_target("t2", TargetProgress::Fuzzing)
            .unwrap();
        let stats = campaign.stats();
        assert_eq!(stats.total_targets, 3);
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.queued, 1);
        assert_eq!(stats.total_findings, 1);
        assert!(stats.overall_progress_pct > 0.0);
    }

    #[test]
    fn test_operator_deconfliction() {
        let mut decon = OperatorDeconfliction::new();
        decon.assign("t1", "op-a").unwrap();
        assert_eq!(decon.assigned_to("t1"), Some("op-a"));
        assert!(decon.assign("t1", "op-b").is_err());
        decon.assign("t1", "op-a").unwrap(); // same operator OK
        let targets = decon.targets_for_operator("op-a");
        assert_eq!(targets, vec!["t1".to_string()]);
        decon.release("t1");
        assert_eq!(decon.assigned_to("t1"), None);
    }

    #[test]
    fn test_dependency_graph_topological_order() {
        let mut deps = DependencyGraph::new();
        deps.add_dependency("exploit", "fuzz");
        deps.add_dependency("fuzz", "recon");
        let targets = vec![
            "recon".to_string(),
            "fuzz".to_string(),
            "exploit".to_string(),
        ];
        let order = deps.topological_order(&targets);
        let recon_pos = order.iter().position(|t| t == "recon").unwrap();
        let fuzz_pos = order.iter().position(|t| t == "fuzz").unwrap();
        let exploit_pos = order.iter().position(|t| t == "exploit").unwrap();
        assert!(recon_pos < fuzz_pos);
        assert!(fuzz_pos < exploit_pos);
    }

    #[test]
    fn test_campaign_manager_multiple_campaigns() {
        let mut mgr = CampaignManagerV2::new();
        let c1 = mgr.create_campaign(cid("c1"), "First".to_string(), 3);
        c1.start().unwrap();
        let c2 = mgr.create_campaign(cid("c2"), "Second".to_string(), 5);
        c2.start().unwrap();
        mgr.create_campaign(cid("c3"), "Third".to_string(), 2);
        assert_eq!(mgr.campaign_count(), 3);
        assert_eq!(mgr.active_campaigns().len(), 2);
    }

    #[test]
    fn test_target_progress_completion_pct() {
        assert_eq!(TargetProgress::Queued.completion_pct(), 0);
        assert_eq!(TargetProgress::Fuzzing.completion_pct(), 50);
        assert_eq!(TargetProgress::Done.completion_pct(), 100);
        assert!(TargetProgress::Done.is_terminal());
        assert!(TargetProgress::Failed.is_terminal());
        assert!(!TargetProgress::Fuzzing.is_terminal());
    }

    #[test]
    fn test_campaign_state_display() {
        assert_eq!(format!("{}", CampaignState::Active), "active");
        assert_eq!(format!("{}", CampaignState::Paused), "paused");
    }

    #[test]
    fn test_simultaneous_hit_config() {
        let config = SimultaneousHitConfig {
            enabled: true,
            target_ids: vec!["t1".to_string(), "t2".to_string()],
            sync_phase: TargetProgress::Fuzzing,
            max_time_skew_ms: 500,
        };
        assert!(config.enabled);
        assert_eq!(config.target_ids.len(), 2);
    }
}
