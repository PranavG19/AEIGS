use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::phase_orchestrator_v2::{PhaseId, PhaseOutcome, PhaseStatus};
use crate::pipeline_executor_v3::{
    PipelineEvent, PipelineExecutorError, PipelineExecutorV3, PipelineV3Config,
};

fn make_success_outcome(phase: PhaseId) -> PhaseOutcome {
    PhaseOutcome {
        phase,
        status: PhaseStatus::Completed,
        duration: Duration::from_millis(50),
        operations_applied: 3,
        findings_count: 1,
        endpoints_discovered: 2,
    }
}

fn make_default_config(target: &str) -> PipelineV3Config {
    PipelineV3Config {
        target_url: target.to_string(),
        ..PipelineV3Config::default()
    }
}

#[test]
fn full_pipeline_runs_all_phases() {
    let config = make_default_config("http://127.0.0.1:3000");
    let phase_count = config.enabled_phases.len();
    let mut executor = PipelineExecutorV3::new(config);

    let invoked = Arc::new(Mutex::new(Vec::new()));
    let inv = invoked.clone();
    executor.set_executor(Box::new(move |phase| {
        inv.lock().unwrap().push(phase);
        Ok(make_success_outcome(phase))
    }));

    let summary = executor.execute().expect("pipeline should succeed");
    assert_eq!(summary.phases_executed, phase_count as u32);
    assert_eq!(summary.phases_failed, 0);
    assert_eq!(summary.total_findings, phase_count as u64);
    assert_eq!(summary.iterations_completed, 1);

    let phases = invoked.lock().unwrap();
    assert_eq!(phases.len(), phase_count);
    assert_eq!(phases[0], PhaseId::Recon);
}

#[test]
fn empty_target_returns_error() {
    let config = PipelineV3Config::default();
    let mut executor = PipelineExecutorV3::new(config);
    executor.set_executor(Box::new(|phase| Ok(make_success_outcome(phase))));

    let result = executor.execute();
    assert!(result.is_err());
    match result.unwrap_err() {
        PipelineExecutorError::InvalidConfig(msg) => {
            assert!(msg.contains("target_url"));
        }
        other => panic!("expected InvalidConfig, got {:?}", other),
    }
}

#[test]
fn no_executor_returns_error() {
    let config = make_default_config("http://127.0.0.1:3000");
    let mut executor = PipelineExecutorV3::new(config);

    let result = executor.execute();
    assert!(matches!(
        result.unwrap_err(),
        PipelineExecutorError::NoExecutor
    ));
}

#[test]
fn fail_fast_stops_on_first_failure() {
    let mut config = make_default_config("http://127.0.0.1:3000");
    config.fail_fast = true;

    let mut executor = PipelineExecutorV3::new(config);
    executor.set_executor(Box::new(|phase| {
        if phase == PhaseId::Crawl {
            Err("crawl exploded".to_string())
        } else {
            Ok(make_success_outcome(phase))
        }
    }));

    let result = executor.execute();
    assert!(result.is_err());
    match result.unwrap_err() {
        PipelineExecutorError::PhaseFailed { phase, error } => {
            assert_eq!(phase, PhaseId::Crawl);
            assert_eq!(error, "crawl exploded");
        }
        other => panic!("expected PhaseFailed, got {:?}", other),
    }
}

#[test]
fn non_fail_fast_continues_after_failure() {
    let config = make_default_config("http://127.0.0.1:3000");
    let phase_count = config.enabled_phases.len();

    let mut executor = PipelineExecutorV3::new(config);
    executor.set_executor(Box::new(|phase| {
        if phase == PhaseId::Fuzz {
            Err("fuzz error".to_string())
        } else {
            Ok(make_success_outcome(phase))
        }
    }));

    let summary = executor.execute().expect("should continue past failure");
    assert_eq!(summary.phases_failed, 1);
    assert_eq!(summary.phases_executed, (phase_count - 1) as u32);
}

#[test]
fn multiple_iterations_rerun_convergence_phases() {
    let mut config = make_default_config("http://127.0.0.1:3000");
    config.max_iterations = 3;

    let invoked = Arc::new(Mutex::new(Vec::new()));
    let inv = invoked.clone();

    let mut executor = PipelineExecutorV3::new(config);
    executor.set_executor(Box::new(move |phase| {
        inv.lock().unwrap().push(phase);
        Ok(make_success_outcome(phase))
    }));

    let summary = executor.execute().expect("should succeed");
    assert_eq!(summary.iterations_completed, 3);

    let phases = invoked.lock().unwrap();
    let fuzz_count = phases.iter().filter(|&&p| p == PhaseId::Fuzz).count();
    assert_eq!(fuzz_count, 3, "fuzz should run in all 3 iterations");

    let recon_count = phases.iter().filter(|&&p| p == PhaseId::Recon).count();
    assert_eq!(recon_count, 1, "recon should only run in iteration 0");
}

#[test]
fn event_callback_receives_events() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();

    let config = PipelineV3Config {
        target_url: "http://127.0.0.1:3000".to_string(),
        enabled_phases: vec![PhaseId::Recon],
        event_callback: Some(Arc::new(move |event| {
            ev.lock().unwrap().push(format!("{:?}", event));
        })),
        ..PipelineV3Config::default()
    };

    let mut executor = PipelineExecutorV3::new(config);
    executor.set_executor(Box::new(|phase| Ok(make_success_outcome(phase))));

    executor.execute().expect("should succeed");

    let captured = events.lock().unwrap();
    assert!(
        captured.len() >= 3,
        "should have start + phase + complete events"
    );
    assert!(captured[0].contains("PipelineStarted"));
    assert!(captured.last().unwrap().contains("PipelineCompleted"));
}

#[test]
fn custom_phase_subset() {
    let config = PipelineV3Config {
        target_url: "http://127.0.0.1:3000".to_string(),
        enabled_phases: vec![PhaseId::Recon, PhaseId::Report],
        ..PipelineV3Config::default()
    };

    let mut executor = PipelineExecutorV3::new(config);
    executor.set_executor(Box::new(|phase| Ok(make_success_outcome(phase))));

    let summary = executor.execute().expect("should succeed");
    assert_eq!(summary.phases_executed, 2);
}

#[test]
fn phase_timings_are_tracked() {
    let config = make_default_config("http://127.0.0.1:3000");
    let mut executor = PipelineExecutorV3::new(config);
    executor.set_executor(Box::new(|phase| Ok(make_success_outcome(phase))));

    let summary = executor.execute().expect("should succeed");
    assert!(summary.phase_timings.contains_key(&PhaseId::Recon));
    assert!(summary.phase_timings.contains_key(&PhaseId::Report));
}

#[test]
fn results_accessible_after_execution() {
    let config = PipelineV3Config {
        target_url: "http://127.0.0.1:3000".to_string(),
        enabled_phases: vec![PhaseId::Recon, PhaseId::Crawl],
        ..PipelineV3Config::default()
    };

    let mut executor = PipelineExecutorV3::new(config);
    executor.set_executor(Box::new(|phase| Ok(make_success_outcome(phase))));

    executor.execute().expect("should succeed");

    let results = executor.results();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].phase, PhaseId::Recon);
    assert!(results[0].error.is_none());
}
