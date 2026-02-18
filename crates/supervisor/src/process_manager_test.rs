#[cfg(test)]
mod tests {
    use crate::process_manager::{
        ComponentId, ManagedProcess, ProcessConfig, ProcessManager, ProcessManagerError,
        ProcessState,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_config(component: ComponentId) -> ProcessConfig {
        ProcessConfig::new(component, PathBuf::from("/opt/aegis/bin/test"))
    }

    #[test]
    fn register_and_retrieve_process() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::KnowledgeGraph))
            .unwrap();

        let process = manager.get_process(ComponentId::KnowledgeGraph).unwrap();
        assert_eq!(process.state, ProcessState::NotStarted);
        assert!(process.pid.is_none());
    }

    #[test]
    fn duplicate_registration_fails() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::Fuzzing))
            .unwrap();
        let result = manager.register(test_config(ComponentId::Fuzzing));
        assert!(matches!(
            result,
            Err(ProcessManagerError::ComponentAlreadyRegistered(ComponentId::Fuzzing))
        ));
    }

    #[test]
    fn spawn_order_preserved() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::KnowledgeGraph))
            .unwrap();
        manager
            .register(test_config(ComponentId::Fuzzing))
            .unwrap();
        manager
            .register(test_config(ComponentId::Reporting))
            .unwrap();

        let order = manager.spawn_order();
        assert_eq!(order[0], ComponentId::KnowledgeGraph);
        assert_eq!(order[1], ComponentId::Fuzzing);
        assert_eq!(order[2], ComponentId::Reporting);
    }

    #[test]
    fn mark_started_updates_state() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::PassiveRecon))
            .unwrap();
        manager
            .mark_started(ComponentId::PassiveRecon, 12345)
            .unwrap();

        let process = manager.get_process(ComponentId::PassiveRecon).unwrap();
        assert_eq!(process.state, ProcessState::Running);
        assert_eq!(process.pid, Some(12345));
        assert!(process.last_started.is_some());
    }

    #[test]
    fn mark_stopped_with_zero_exit_sets_stopped() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::Reporting))
            .unwrap();
        manager
            .mark_started(ComponentId::Reporting, 100)
            .unwrap();
        manager.mark_stopped(ComponentId::Reporting, 0).unwrap();

        let process = manager.get_process(ComponentId::Reporting).unwrap();
        assert_eq!(process.state, ProcessState::Stopped);
        assert_eq!(process.exit_code, Some(0));
        assert!(process.pid.is_none());
    }

    #[test]
    fn mark_stopped_with_nonzero_exit_sets_failed() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::Fuzzing))
            .unwrap();
        manager.mark_started(ComponentId::Fuzzing, 200).unwrap();
        manager.mark_stopped(ComponentId::Fuzzing, 1).unwrap();

        let process = manager.get_process(ComponentId::Fuzzing).unwrap();
        assert_eq!(process.state, ProcessState::Failed);
        assert_eq!(process.exit_code, Some(1));
    }

    #[test]
    fn restart_increments_count_and_returns_backoff() {
        let config = test_config(ComponentId::Enumeration)
            .with_max_restarts(3)
            .with_restart_backoff(Duration::from_secs(1));
        let mut manager = ProcessManager::new();
        manager.register(config).unwrap();

        let backoff1 = manager
            .request_restart(ComponentId::Enumeration)
            .unwrap();
        assert_eq!(backoff1, Duration::from_secs(1));

        let backoff2 = manager
            .request_restart(ComponentId::Enumeration)
            .unwrap();
        assert_eq!(backoff2, Duration::from_secs(2));

        let backoff3 = manager
            .request_restart(ComponentId::Enumeration)
            .unwrap();
        assert_eq!(backoff3, Duration::from_secs(4));

        let result = manager.request_restart(ComponentId::Enumeration);
        assert!(matches!(
            result,
            Err(ProcessManagerError::MaxRestartsExceeded(ComponentId::Enumeration))
        ));
    }

    #[test]
    fn running_and_failed_counts() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::KnowledgeGraph))
            .unwrap();
        manager
            .register(test_config(ComponentId::Fuzzing))
            .unwrap();
        manager
            .register(test_config(ComponentId::Reporting))
            .unwrap();

        assert_eq!(manager.running_count(), 0);

        manager
            .mark_started(ComponentId::KnowledgeGraph, 1)
            .unwrap();
        manager.mark_started(ComponentId::Fuzzing, 2).unwrap();
        assert_eq!(manager.running_count(), 2);

        manager.mark_stopped(ComponentId::Fuzzing, 1).unwrap();
        assert_eq!(manager.running_count(), 1);
        assert_eq!(manager.failed_count(), 1);
    }

    #[test]
    fn components_in_state_filters_correctly() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::KnowledgeGraph))
            .unwrap();
        manager
            .register(test_config(ComponentId::PassiveRecon))
            .unwrap();
        manager
            .register(test_config(ComponentId::Fuzzing))
            .unwrap();

        manager
            .mark_started(ComponentId::KnowledgeGraph, 1)
            .unwrap();
        manager
            .mark_started(ComponentId::PassiveRecon, 2)
            .unwrap();

        let running = manager.components_in_state(ProcessState::Running);
        assert_eq!(running.len(), 2);

        let not_started = manager.components_in_state(ProcessState::NotStarted);
        assert_eq!(not_started.len(), 1);
        assert_eq!(not_started[0], ComponentId::Fuzzing);
    }

    #[test]
    fn shutdown_all_stops_running_processes() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::KnowledgeGraph))
            .unwrap();
        manager
            .register(test_config(ComponentId::Fuzzing))
            .unwrap();

        manager
            .mark_started(ComponentId::KnowledgeGraph, 1)
            .unwrap();
        manager.mark_started(ComponentId::Fuzzing, 2).unwrap();

        let stopped = manager.shutdown_all();
        assert_eq!(stopped.len(), 2);
        assert_eq!(manager.running_count(), 0);

        let all_stopped = manager.components_in_state(ProcessState::Stopped);
        assert_eq!(all_stopped.len(), 2);
    }

    #[test]
    fn config_builder_methods() {
        let config = ProcessConfig::new(ComponentId::Fuzzing, PathBuf::from("/bin/fuzz"))
            .with_arguments(vec!["--fast".to_string()])
            .with_max_restarts(5)
            .with_restart_backoff(Duration::from_secs(2))
            .with_memory_limit(1024 * 1024 * 512)
            .with_cpu_limit(80);

        assert_eq!(config.arguments, vec!["--fast"]);
        assert_eq!(config.max_restarts, 5);
        assert_eq!(config.restart_backoff_base, Duration::from_secs(2));
        assert_eq!(config.memory_limit_bytes, Some(1024 * 1024 * 512));
        assert_eq!(config.cpu_limit_percent, Some(80));
    }

    #[test]
    fn managed_process_backoff_grows_exponentially() {
        let config =
            test_config(ComponentId::Watchdog).with_restart_backoff(Duration::from_millis(100));
        let mut process = ManagedProcess::new(config);

        assert_eq!(process.backoff_duration(), Duration::from_millis(100));
        process.mark_restarting();
        assert_eq!(process.backoff_duration(), Duration::from_millis(200));
        process.mark_restarting();
        assert_eq!(process.backoff_duration(), Duration::from_millis(400));
        process.mark_restarting();
        assert_eq!(process.backoff_duration(), Duration::from_millis(800));
    }

    #[test]
    fn not_found_errors_for_unknown_components() {
        let mut manager = ProcessManager::new();

        assert!(manager.get_process(ComponentId::Fuzzing).is_none());
        assert!(matches!(
            manager.mark_started(ComponentId::Fuzzing, 1),
            Err(ProcessManagerError::ComponentNotFound(ComponentId::Fuzzing))
        ));
        assert!(matches!(
            manager.mark_stopped(ComponentId::Fuzzing, 0),
            Err(ProcessManagerError::ComponentNotFound(ComponentId::Fuzzing))
        ));
        assert!(matches!(
            manager.request_restart(ComponentId::Fuzzing),
            Err(ProcessManagerError::ComponentNotFound(ComponentId::Fuzzing))
        ));
    }

    #[test]
    fn component_id_display() {
        assert_eq!(ComponentId::KnowledgeGraph.to_string(), "knowledge-graph");
        assert_eq!(ComponentId::PassiveRecon.to_string(), "passive-recon");
        assert_eq!(ComponentId::Enumeration.to_string(), "enumeration");
        assert_eq!(ComponentId::Fuzzing.to_string(), "fuzzing");
        assert_eq!(ComponentId::TaintAnalysis.to_string(), "taint-analysis");
        assert_eq!(ComponentId::ChainSynthesis.to_string(), "chain-synthesis");
        assert_eq!(ComponentId::Reporting.to_string(), "reporting");
        assert_eq!(ComponentId::Watchdog.to_string(), "watchdog");
        assert_eq!(
            ComponentId::HypothesisEngine.to_string(),
            "hypothesis-engine"
        );
    }

    #[test]
    fn error_display_is_descriptive() {
        let err = ProcessManagerError::ComponentAlreadyRegistered(ComponentId::Fuzzing);
        assert!(err.to_string().contains("already registered"));

        let err = ProcessManagerError::ComponentNotFound(ComponentId::Reporting);
        assert!(err.to_string().contains("not found"));

        let err = ProcessManagerError::MaxRestartsExceeded(ComponentId::Watchdog);
        assert!(err.to_string().contains("max restarts"));

        let err =
            ProcessManagerError::SpawnFailed(ComponentId::Fuzzing, "permission denied".to_string());
        assert!(err.to_string().contains("spawn failed"));
        assert!(err.to_string().contains("permission denied"));
    }

    #[test]
    fn all_processes_iterates_all_registered() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::KnowledgeGraph))
            .unwrap();
        manager
            .register(test_config(ComponentId::Fuzzing))
            .unwrap();

        let all: Vec<_> = manager.all_processes().collect();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn get_process_mut_allows_modification() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::Fuzzing))
            .unwrap();

        let process = manager.get_process_mut(ComponentId::Fuzzing).unwrap();
        process.mark_started(999);
        assert_eq!(process.state, ProcessState::Running);
        assert_eq!(process.pid, Some(999));
    }

    #[test]
    fn default_creates_empty_manager() {
        let manager = ProcessManager::default();
        assert_eq!(manager.running_count(), 0);
        assert_eq!(manager.failed_count(), 0);
        assert!(manager.spawn_order().is_empty());
    }

    #[test]
    fn mark_started_clears_previous_exit_code() {
        let mut manager = ProcessManager::new();
        manager
            .register(test_config(ComponentId::Reporting))
            .unwrap();
        manager
            .mark_started(ComponentId::Reporting, 100)
            .unwrap();
        manager.mark_stopped(ComponentId::Reporting, 1).unwrap();

        let process = manager.get_process(ComponentId::Reporting).unwrap();
        assert_eq!(process.exit_code, Some(1));

        manager
            .mark_started(ComponentId::Reporting, 200)
            .unwrap();
        let process = manager.get_process(ComponentId::Reporting).unwrap();
        assert!(process.exit_code.is_none());
    }
}
