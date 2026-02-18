use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentId {
    KnowledgeGraph,
    PassiveRecon,
    Enumeration,
    Fuzzing,
    TaintAnalysis,
    ChainSynthesis,
    Reporting,
    Watchdog,
    HypothesisEngine,
}

impl std::fmt::Display for ComponentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::KnowledgeGraph => "knowledge-graph",
            Self::PassiveRecon => "passive-recon",
            Self::Enumeration => "enumeration",
            Self::Fuzzing => "fuzzing",
            Self::TaintAnalysis => "taint-analysis",
            Self::ChainSynthesis => "chain-synthesis",
            Self::Reporting => "reporting",
            Self::Watchdog => "watchdog",
            Self::HypothesisEngine => "hypothesis-engine",
        };
        write!(f, "{name}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    NotStarted,
    Running,
    Stopped,
    Failed,
    Restarting,
}

#[derive(Debug, Clone)]
pub struct ProcessConfig {
    pub component: ComponentId,
    pub binary_path: PathBuf,
    pub arguments: Vec<String>,
    pub max_restarts: u32,
    pub restart_backoff_base: Duration,
    pub memory_limit_bytes: Option<u64>,
    pub cpu_limit_percent: Option<u32>,
}

impl ProcessConfig {
    pub fn new(component: ComponentId, binary_path: PathBuf) -> Self {
        Self {
            component,
            binary_path,
            arguments: Vec::new(),
            max_restarts: 3,
            restart_backoff_base: Duration::from_secs(1),
            memory_limit_bytes: None,
            cpu_limit_percent: None,
        }
    }

    pub fn with_arguments(mut self, args: Vec<String>) -> Self {
        self.arguments = args;
        self
    }

    pub fn with_max_restarts(mut self, max: u32) -> Self {
        self.max_restarts = max;
        self
    }

    pub fn with_restart_backoff(mut self, base: Duration) -> Self {
        self.restart_backoff_base = base;
        self
    }

    pub fn with_memory_limit(mut self, bytes: u64) -> Self {
        self.memory_limit_bytes = Some(bytes);
        self
    }

    pub fn with_cpu_limit(mut self, percent: u32) -> Self {
        self.cpu_limit_percent = Some(percent);
        self
    }
}

#[derive(Debug)]
pub struct ManagedProcess {
    pub config: ProcessConfig,
    pub state: ProcessState,
    pub pid: Option<u32>,
    pub restart_count: u32,
    pub last_started: Option<Instant>,
    pub last_stopped: Option<Instant>,
    pub exit_code: Option<i32>,
}

impl ManagedProcess {
    pub fn new(config: ProcessConfig) -> Self {
        Self {
            config,
            state: ProcessState::NotStarted,
            pid: None,
            restart_count: 0,
            last_started: None,
            last_stopped: None,
            exit_code: None,
        }
    }

    pub fn can_restart(&self) -> bool {
        self.restart_count < self.config.max_restarts
    }

    pub fn backoff_duration(&self) -> Duration {
        let multiplier = 2u64.saturating_pow(self.restart_count);
        self.config
            .restart_backoff_base
            .saturating_mul(multiplier as u32)
    }

    pub fn mark_started(&mut self, pid: u32) {
        self.state = ProcessState::Running;
        self.pid = Some(pid);
        self.last_started = Some(Instant::now());
        self.exit_code = None;
    }

    pub fn mark_stopped(&mut self, exit_code: i32) {
        self.pid = None;
        self.last_stopped = Some(Instant::now());
        self.exit_code = Some(exit_code);
        if exit_code == 0 {
            self.state = ProcessState::Stopped;
        } else {
            self.state = ProcessState::Failed;
        }
    }

    pub fn mark_restarting(&mut self) {
        self.state = ProcessState::Restarting;
        self.restart_count += 1;
    }
}

#[derive(Debug)]
pub enum ProcessManagerError {
    ComponentAlreadyRegistered(ComponentId),
    ComponentNotFound(ComponentId),
    MaxRestartsExceeded(ComponentId),
    SpawnFailed(ComponentId, String),
}

impl std::fmt::Display for ProcessManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ComponentAlreadyRegistered(id) => {
                write!(f, "component already registered: {id}")
            }
            Self::ComponentNotFound(id) => write!(f, "component not found: {id}"),
            Self::MaxRestartsExceeded(id) => write!(f, "max restarts exceeded for: {id}"),
            Self::SpawnFailed(id, reason) => write!(f, "spawn failed for {id}: {reason}"),
        }
    }
}

impl std::error::Error for ProcessManagerError {}

pub struct ProcessManager {
    processes: HashMap<ComponentId, ManagedProcess>,
    spawn_order: Vec<ComponentId>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            spawn_order: Vec::new(),
        }
    }

    pub fn register(&mut self, config: ProcessConfig) -> Result<(), ProcessManagerError> {
        let component = config.component;
        if self.processes.contains_key(&component) {
            return Err(ProcessManagerError::ComponentAlreadyRegistered(component));
        }
        self.spawn_order.push(component);
        self.processes
            .insert(component, ManagedProcess::new(config));
        Ok(())
    }

    pub fn get_process(&self, component: ComponentId) -> Option<&ManagedProcess> {
        self.processes.get(&component)
    }

    pub fn get_process_mut(&mut self, component: ComponentId) -> Option<&mut ManagedProcess> {
        self.processes.get_mut(&component)
    }

    pub fn spawn_order(&self) -> &[ComponentId] {
        &self.spawn_order
    }

    pub fn all_processes(&self) -> impl Iterator<Item = (&ComponentId, &ManagedProcess)> {
        self.processes.iter()
    }

    pub fn running_count(&self) -> usize {
        self.processes
            .values()
            .filter(|p| p.state == ProcessState::Running)
            .count()
    }

    pub fn failed_count(&self) -> usize {
        self.processes
            .values()
            .filter(|p| p.state == ProcessState::Failed)
            .count()
    }

    pub fn request_restart(
        &mut self,
        component: ComponentId,
    ) -> Result<Duration, ProcessManagerError> {
        let process = self
            .processes
            .get_mut(&component)
            .ok_or(ProcessManagerError::ComponentNotFound(component))?;

        if !process.can_restart() {
            return Err(ProcessManagerError::MaxRestartsExceeded(component));
        }

        let backoff = process.backoff_duration();
        process.mark_restarting();
        Ok(backoff)
    }

    pub fn mark_started(
        &mut self,
        component: ComponentId,
        pid: u32,
    ) -> Result<(), ProcessManagerError> {
        let process = self
            .processes
            .get_mut(&component)
            .ok_or(ProcessManagerError::ComponentNotFound(component))?;
        process.mark_started(pid);
        Ok(())
    }

    pub fn mark_stopped(
        &mut self,
        component: ComponentId,
        exit_code: i32,
    ) -> Result<(), ProcessManagerError> {
        let process = self
            .processes
            .get_mut(&component)
            .ok_or(ProcessManagerError::ComponentNotFound(component))?;
        process.mark_stopped(exit_code);
        Ok(())
    }

    pub fn components_in_state(&self, state: ProcessState) -> Vec<ComponentId> {
        self.processes
            .iter()
            .filter(|(_, p)| p.state == state)
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn shutdown_all(&mut self) -> Vec<ComponentId> {
        let running: Vec<ComponentId> = self.components_in_state(ProcessState::Running);
        for &component in running.iter().rev() {
            if let Some(process) = self.processes.get_mut(&component) {
                process.state = ProcessState::Stopped;
                process.pid = None;
            }
        }
        running
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}
