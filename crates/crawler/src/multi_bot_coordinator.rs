use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Unique identifier for a scanning bot instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BotId(pub u32);

/// Status of a scanning bot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BotStatus {
    Idle,
    Scanning,
    WaitingForTask,
    RateLimited,
    Failed,
    Shutdown,
}

/// A task assigned to a bot for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub task_id: u64,
    pub url: String,
    pub method: String,
    pub task_type: ScanTaskType,
    pub priority: u32,
    pub assigned_bot: Option<BotId>,
    pub retries: u32,
    pub max_retries: u32,
}

/// Type of scanning task to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScanTaskType {
    Crawl,
    Fuzz,
    FormSubmit,
    AuthTest,
    RaceCondition,
    ApiDiscovery,
}

/// A finding shared across all bots to inform scanning strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFinding {
    pub url: String,
    pub finding_type: String,
    pub severity: FindingSeverity,
    pub discovered_by: BotId,
    pub timestamp_ms: u64,
    pub details: String,
}

/// Severity level of a shared finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Session token shared across bots for authenticated scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSession {
    pub session_id: String,
    pub cookies: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub token: Option<String>,
    pub expires_at_ms: Option<u64>,
    pub role: String,
}

/// Statistics for a single bot instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BotStats {
    pub tasks_completed: u64,
    pub tasks_failed: u64,
    pub findings_count: u64,
    pub avg_response_ms: f64,
    pub last_active_ms: u64,
    pub rate_limit_hits: u32,
}

/// Configuration for multi-bot coordination.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    pub initial_bot_count: u32,
    pub max_bot_count: u32,
    pub min_bot_count: u32,
    pub task_timeout: Duration,
    pub rebalance_interval: Duration,
    pub scale_up_threshold_ms: u64,
    pub scale_down_threshold_ms: u64,
    pub max_retries_per_task: u32,
    pub race_condition_window_ms: u64,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            initial_bot_count: 4,
            max_bot_count: 16,
            min_bot_count: 1,
            task_timeout: Duration::from_secs(30),
            rebalance_interval: Duration::from_secs(10),
            scale_up_threshold_ms: 5000,
            scale_down_threshold_ms: 100,
            max_retries_per_task: 3,
            race_condition_window_ms: 50,
        }
    }
}

impl CoordinatorConfig {
    pub fn with_initial_bot_count(mut self, count: u32) -> Self {
        self.initial_bot_count = count;
        self
    }

    pub fn with_max_bot_count(mut self, count: u32) -> Self {
        self.max_bot_count = count;
        self
    }

    pub fn with_task_timeout(mut self, timeout: Duration) -> Self {
        self.task_timeout = timeout;
        self
    }

    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries_per_task = retries;
        self
    }
}

/// Scaling decision for bot pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScaleDecision {
    ScaleUp(u32),
    ScaleDown(u32),
    NoChange,
}

/// Multi-bot scanner coordinator that manages task distribution, shared state,
/// session sharing, and auto-scaling across a pool of scanning bot instances.
///
/// Each bot receives tasks from a priority queue, reports findings to shared state,
/// and the coordinator rebalances work based on bot performance and target response times.
pub struct MultiBotCoordinator {
    config: CoordinatorConfig,
    task_queue: Arc<Mutex<VecDeque<ScanTask>>>,
    bot_statuses: Arc<Mutex<HashMap<BotId, BotStatus>>>,
    bot_stats: Arc<Mutex<HashMap<BotId, BotStats>>>,
    shared_findings: Arc<Mutex<Vec<SharedFinding>>>,
    shared_sessions: Arc<Mutex<Vec<SharedSession>>>,
    completed_urls: Arc<Mutex<HashSet<String>>>,
    next_task_id: Arc<Mutex<u64>>,
    next_bot_id: Arc<Mutex<u32>>,
}

impl MultiBotCoordinator {
    pub fn new(config: CoordinatorConfig) -> Self {
        Self {
            config,
            task_queue: Arc::new(Mutex::new(VecDeque::new())),
            bot_statuses: Arc::new(Mutex::new(HashMap::new())),
            bot_stats: Arc::new(Mutex::new(HashMap::new())),
            shared_findings: Arc::new(Mutex::new(Vec::new())),
            shared_sessions: Arc::new(Mutex::new(Vec::new())),
            completed_urls: Arc::new(Mutex::new(HashSet::new())),
            next_task_id: Arc::new(Mutex::new(1)),
            next_bot_id: Arc::new(Mutex::new(0)),
        }
    }

    /// Register a new bot instance and return its ID.
    pub async fn register_bot(&self) -> BotId {
        let mut id = self.next_bot_id.lock().await;
        let bot_id = BotId(*id);
        *id += 1;

        self.bot_statuses
            .lock()
            .await
            .insert(bot_id, BotStatus::Idle);
        self.bot_stats
            .lock()
            .await
            .insert(bot_id, BotStats::default());

        bot_id
    }

    /// Initialize the bot pool with the configured initial count.
    pub async fn initialize_pool(&self) -> Vec<BotId> {
        let mut bots = Vec::new();
        for _ in 0..self.config.initial_bot_count {
            bots.push(self.register_bot().await);
        }
        bots
    }

    /// Enqueue a new scanning task.
    pub async fn enqueue_task(
        &self,
        url: &str,
        method: &str,
        task_type: ScanTaskType,
        priority: u32,
    ) -> u64 {
        let mut id = self.next_task_id.lock().await;
        let task_id = *id;
        *id += 1;

        let task = ScanTask {
            task_id,
            url: url.to_string(),
            method: method.to_string(),
            task_type,
            priority,
            assigned_bot: None,
            retries: 0,
            max_retries: self.config.max_retries_per_task,
        };

        let mut queue = self.task_queue.lock().await;
        let insert_pos = queue
            .iter()
            .position(|t| t.priority < priority)
            .unwrap_or(queue.len());
        queue.insert(insert_pos, task);

        task_id
    }

    /// Assign the next available task to a bot.
    ///
    /// Returns None if no tasks are available. Updates bot status to Scanning.
    pub async fn assign_task(&self, bot_id: BotId) -> Option<ScanTask> {
        let mut queue = self.task_queue.lock().await;
        if let Some(mut task) = queue.pop_front() {
            task.assigned_bot = Some(bot_id);
            self.bot_statuses
                .lock()
                .await
                .insert(bot_id, BotStatus::Scanning);
            Some(task)
        } else {
            self.bot_statuses
                .lock()
                .await
                .insert(bot_id, BotStatus::WaitingForTask);
            None
        }
    }

    /// Report that a task completed successfully.
    pub async fn complete_task(&self, bot_id: BotId, task: &ScanTask, response_time_ms: u64) {
        self.completed_urls.lock().await.insert(task.url.clone());

        let mut stats = self.bot_stats.lock().await;
        if let Some(s) = stats.get_mut(&bot_id) {
            let total = s.tasks_completed + s.tasks_failed;
            s.avg_response_ms =
                (s.avg_response_ms * total as f64 + response_time_ms as f64) / (total + 1) as f64;
            s.tasks_completed += 1;
            s.last_active_ms = current_time_ms();
        }

        self.bot_statuses
            .lock()
            .await
            .insert(bot_id, BotStatus::Idle);
    }

    /// Report a task failure and optionally re-queue.
    pub async fn fail_task(&self, bot_id: BotId, mut task: ScanTask) {
        {
            let mut stats = self.bot_stats.lock().await;
            if let Some(s) = stats.get_mut(&bot_id) {
                s.tasks_failed += 1;
                s.last_active_ms = current_time_ms();
            }
        }

        if task.retries < task.max_retries {
            task.retries += 1;
            task.assigned_bot = None;
            let mut queue = self.task_queue.lock().await;
            queue.push_back(task);
        }

        self.bot_statuses
            .lock()
            .await
            .insert(bot_id, BotStatus::Idle);
    }

    /// Record that a bot hit a rate limit.
    pub async fn report_rate_limit(&self, bot_id: BotId) {
        self.bot_statuses
            .lock()
            .await
            .insert(bot_id, BotStatus::RateLimited);

        let mut stats = self.bot_stats.lock().await;
        if let Some(s) = stats.get_mut(&bot_id) {
            s.rate_limit_hits += 1;
        }
    }

    /// Share a finding across all bots.
    pub async fn share_finding(&self, finding: SharedFinding) {
        let bot_id = finding.discovered_by;
        self.shared_findings.lock().await.push(finding);

        let mut stats = self.bot_stats.lock().await;
        if let Some(s) = stats.get_mut(&bot_id) {
            s.findings_count += 1;
        }
    }

    /// Get all shared findings.
    pub async fn get_findings(&self) -> Vec<SharedFinding> {
        self.shared_findings.lock().await.clone()
    }

    /// Share an authenticated session across all bots.
    pub async fn share_session(&self, session: SharedSession) {
        self.shared_sessions.lock().await.push(session);
    }

    /// Get all shared sessions.
    pub async fn get_sessions(&self) -> Vec<SharedSession> {
        self.shared_sessions.lock().await.clone()
    }

    /// Get a session for a specific role.
    pub async fn get_session_for_role(&self, role: &str) -> Option<SharedSession> {
        self.shared_sessions
            .lock()
            .await
            .iter()
            .find(|s| s.role == role)
            .cloned()
    }

    /// Determine scaling decision based on current bot performance.
    ///
    /// Scales up if average response time exceeds the threshold (target is slow),
    /// scales down if response times are very fast and bots are idle.
    pub async fn evaluate_scaling(&self) -> ScaleDecision {
        let stats = self.bot_stats.lock().await;
        let statuses = self.bot_statuses.lock().await;

        let active_count = statuses.len() as u32;
        if active_count == 0 {
            return ScaleDecision::NoChange;
        }

        let avg_response: f64 =
            stats.values().map(|s| s.avg_response_ms).sum::<f64>() / stats.len().max(1) as f64;

        let idle_count = statuses
            .values()
            .filter(|s| matches!(s, BotStatus::Idle | BotStatus::WaitingForTask))
            .count() as u32;

        let rate_limited = statuses
            .values()
            .filter(|s| matches!(s, BotStatus::RateLimited))
            .count() as u32;

        if rate_limited > active_count / 2 {
            let remove = (active_count - self.config.min_bot_count).min(rate_limited);
            if remove > 0 {
                return ScaleDecision::ScaleDown(remove);
            }
        }

        if avg_response > self.config.scale_up_threshold_ms as f64
            && active_count < self.config.max_bot_count
        {
            let add = ((self.config.max_bot_count - active_count) / 2).max(1);
            return ScaleDecision::ScaleUp(add);
        }

        if avg_response < self.config.scale_down_threshold_ms as f64
            && idle_count > active_count / 2
            && active_count > self.config.min_bot_count
        {
            let total_completed: u64 = stats.values().map(|s| s.tasks_completed).sum();
            if total_completed > 0 {
                let remove = (idle_count / 2).min(active_count - self.config.min_bot_count);
                if remove > 0 {
                    return ScaleDecision::ScaleDown(remove);
                }
            }
        }

        ScaleDecision::NoChange
    }

    /// Redistribute tasks from overloaded bots to idle ones.
    pub async fn rebalance(&self) -> u32 {
        let statuses = self.bot_statuses.lock().await;
        let queue = self.task_queue.lock().await;

        let idle_bots: Vec<BotId> = statuses
            .iter()
            .filter(|(_, s)| matches!(s, BotStatus::Idle | BotStatus::WaitingForTask))
            .map(|(id, _)| *id)
            .collect();

        let pending = queue.len();
        idle_bots.len().min(pending) as u32
    }

    /// Enqueue simultaneous requests for race condition testing.
    ///
    /// Creates multiple identical tasks that should be executed simultaneously
    /// by different bots to test for TOCTOU and race condition vulnerabilities.
    pub async fn enqueue_race_condition_test(
        &self,
        url: &str,
        method: &str,
        concurrent_count: u32,
    ) -> Vec<u64> {
        let mut task_ids = Vec::new();
        for _ in 0..concurrent_count {
            let id = self
                .enqueue_task(url, method, ScanTaskType::RaceCondition, 10)
                .await;
            task_ids.push(id);
        }
        task_ids
    }

    /// Get current status of all bots.
    pub async fn bot_status_summary(&self) -> HashMap<BotId, BotStatus> {
        self.bot_statuses.lock().await.clone()
    }

    /// Get performance stats for all bots.
    pub async fn bot_stats_summary(&self) -> HashMap<BotId, BotStats> {
        self.bot_stats.lock().await.clone()
    }

    /// Get the number of pending tasks in the queue.
    pub async fn pending_task_count(&self) -> usize {
        self.task_queue.lock().await.len()
    }

    /// Check if a URL has already been scanned.
    pub async fn is_url_completed(&self, url: &str) -> bool {
        self.completed_urls.lock().await.contains(url)
    }

    /// Shut down a specific bot.
    pub async fn shutdown_bot(&self, bot_id: BotId) {
        self.bot_statuses
            .lock()
            .await
            .insert(bot_id, BotStatus::Shutdown);
    }

    /// Access the coordinator configuration.
    pub fn config(&self) -> &CoordinatorConfig {
        &self.config
    }
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
#[path = "multi_bot_coordinator_test.rs"]
mod multi_bot_coordinator_test;
