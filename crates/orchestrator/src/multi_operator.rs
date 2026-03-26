/// Multi-Operator Collaboration — role-based access control, session sharing,
/// task assignment, conflict prevention, audit log with attribution, E2E encrypted comms.
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Operator roles with hierarchical permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorRole {
    Admin,
    Operator,
    Observer,
}

impl OperatorRole {
    pub fn can_execute_tasks(&self) -> bool {
        matches!(self, Self::Admin | Self::Operator)
    }

    pub fn can_manage_operators(&self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn can_view_findings(&self) -> bool {
        true
    }

    pub fn can_modify_config(&self) -> bool {
        matches!(self, Self::Admin)
    }
}

impl std::fmt::Display for OperatorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "Admin"),
            Self::Operator => write!(f, "Operator"),
            Self::Observer => write!(f, "Observer"),
        }
    }
}

/// Unique operator identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperatorId(pub String);

impl std::fmt::Display for OperatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Registered operator with credentials and role.
#[derive(Debug, Clone)]
pub struct Operator {
    pub id: OperatorId,
    pub display_name: String,
    pub role: OperatorRole,
    pub public_key: Vec<u8>,
    pub registered_at: u64,
    pub last_active: u64,
    pub active_session: Option<String>,
}

/// Shared session that multiple operators can join.
#[derive(Debug, Clone)]
pub struct SharedSession {
    pub session_id: String,
    pub created_by: OperatorId,
    pub participants: HashSet<OperatorId>,
    pub created_at: u64,
    pub target_url: String,
    pub description: String,
    pub is_active: bool,
}

impl SharedSession {
    pub fn new(
        session_id: String,
        creator: OperatorId,
        target_url: String,
        description: String,
    ) -> Self {
        Self {
            session_id,
            created_by: creator.clone(),
            participants: {
                let mut s = HashSet::new();
                s.insert(creator);
                s
            },
            created_at: current_timestamp_ms(),
            target_url,
            description,
            is_active: true,
        }
    }

    pub fn join(&mut self, operator: OperatorId) -> bool {
        self.participants.insert(operator)
    }

    pub fn leave(&mut self, operator: &OperatorId) -> bool {
        self.participants.remove(operator)
    }

    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }
}

/// Task assignment state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Pending,
    Assigned,
    InProgress,
    Completed,
    Cancelled,
}

/// A task assigned to an operator.
#[derive(Debug, Clone)]
pub struct OperatorTask {
    pub task_id: String,
    pub session_id: String,
    pub assigned_to: Option<OperatorId>,
    pub assigned_by: OperatorId,
    pub description: String,
    pub target_endpoint: Option<String>,
    pub status: TaskStatus,
    pub created_at: u64,
    pub completed_at: Option<u64>,
}

/// Resource lock for conflict prevention.
#[derive(Debug, Clone)]
pub struct ResourceLock {
    pub resource_id: String,
    pub locked_by: OperatorId,
    pub locked_at: Instant,
    pub ttl: Duration,
}

impl ResourceLock {
    pub fn is_expired(&self) -> bool {
        self.locked_at.elapsed() > self.ttl
    }
}

/// Conflict prevention manager — ensures no two operators target the same endpoint.
#[derive(Debug)]
pub struct ConflictManager {
    pub locks: HashMap<String, ResourceLock>,
    pub default_ttl: Duration,
}

impl ConflictManager {
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            locks: HashMap::new(),
            default_ttl,
        }
    }

    pub fn acquire_lock(
        &mut self,
        resource_id: &str,
        operator: OperatorId,
    ) -> Result<(), ConflictError> {
        self.cleanup_expired();
        if let Some(lock) = self.locks.get(resource_id) {
            if lock.locked_by != operator {
                return Err(ConflictError::ResourceLocked {
                    resource: resource_id.to_string(),
                    held_by: lock.locked_by.clone(),
                });
            }
        }
        self.locks.insert(
            resource_id.to_string(),
            ResourceLock {
                resource_id: resource_id.to_string(),
                locked_by: operator,
                locked_at: Instant::now(),
                ttl: self.default_ttl,
            },
        );
        Ok(())
    }

    pub fn release_lock(
        &mut self,
        resource_id: &str,
        operator: &OperatorId,
    ) -> Result<(), ConflictError> {
        match self.locks.get(resource_id) {
            Some(lock) if &lock.locked_by == operator => {
                self.locks.remove(resource_id);
                Ok(())
            }
            Some(lock) => Err(ConflictError::NotLockOwner {
                resource: resource_id.to_string(),
                held_by: lock.locked_by.clone(),
            }),
            None => Err(ConflictError::LockNotFound(resource_id.to_string())),
        }
    }

    pub fn is_locked(&self, resource_id: &str) -> bool {
        self.locks
            .get(resource_id)
            .map_or(false, |l| !l.is_expired())
    }

    fn cleanup_expired(&mut self) {
        self.locks.retain(|_, lock| !lock.is_expired());
    }

    pub fn active_lock_count(&self) -> usize {
        self.locks.values().filter(|l| !l.is_expired()).count()
    }
}

/// Conflict error types.
#[derive(Debug)]
pub enum ConflictError {
    ResourceLocked {
        resource: String,
        held_by: OperatorId,
    },
    NotLockOwner {
        resource: String,
        held_by: OperatorId,
    },
    LockNotFound(String),
}

impl std::fmt::Display for ConflictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResourceLocked { resource, held_by } => {
                write!(f, "resource '{}' locked by {}", resource, held_by)
            }
            Self::NotLockOwner { resource, held_by } => {
                write!(f, "resource '{}' owned by {}", resource, held_by)
            }
            Self::LockNotFound(r) => write!(f, "no lock found for '{}'", r),
        }
    }
}

/// Audit entry for operator actions with attribution.
#[derive(Debug, Clone)]
pub struct OperatorAuditEntry {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub operator_id: OperatorId,
    pub session_id: String,
    pub action: OperatorAction,
    pub details: String,
}

/// Actions logged in the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorAction {
    Login,
    Logout,
    SessionCreated,
    SessionJoined,
    TaskAssigned,
    TaskCompleted,
    LockAcquired,
    LockReleased,
    FindingReported,
    ConfigModified,
    CommandExecuted,
}

impl std::fmt::Display for OperatorAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Login => "login",
            Self::Logout => "logout",
            Self::SessionCreated => "session_created",
            Self::SessionJoined => "session_joined",
            Self::TaskAssigned => "task_assigned",
            Self::TaskCompleted => "task_completed",
            Self::LockAcquired => "lock_acquired",
            Self::LockReleased => "lock_released",
            Self::FindingReported => "finding_reported",
            Self::ConfigModified => "config_modified",
            Self::CommandExecuted => "command_executed",
        };
        write!(f, "{}", name)
    }
}

/// Audit log with operator attribution.
#[derive(Debug)]
pub struct OperatorAuditLog {
    entries: Vec<OperatorAuditEntry>,
    next_seq: u64,
}

impl OperatorAuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_seq: 1,
        }
    }

    pub fn append(
        &mut self,
        operator_id: OperatorId,
        session_id: String,
        action: OperatorAction,
        details: String,
    ) -> u64 {
        let seq = self.next_seq;
        self.entries.push(OperatorAuditEntry {
            sequence: seq,
            timestamp_ms: current_timestamp_ms(),
            operator_id,
            session_id,
            action,
            details,
        });
        self.next_seq += 1;
        seq
    }

    pub fn entries_by_operator(&self, operator: &OperatorId) -> Vec<&OperatorAuditEntry> {
        self.entries
            .iter()
            .filter(|e| &e.operator_id == operator)
            .collect()
    }

    pub fn entries_by_session(&self, session_id: &str) -> Vec<&OperatorAuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.session_id == session_id)
            .collect()
    }

    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }
}

impl Default for OperatorAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// E2E encrypted communication channel between operators.
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    pub from: OperatorId,
    pub to: OperatorId,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp_ms: u64,
}

/// Message queue for operator-to-operator encrypted comms.
#[derive(Debug)]
pub struct OperatorMessageBus {
    queues: HashMap<OperatorId, VecDeque<EncryptedMessage>>,
}

impl OperatorMessageBus {
    pub fn new() -> Self {
        Self {
            queues: HashMap::new(),
        }
    }

    pub fn send(&mut self, msg: EncryptedMessage) {
        self.queues
            .entry(msg.to.clone())
            .or_default()
            .push_back(msg);
    }

    pub fn receive(&mut self, operator: &OperatorId) -> Vec<EncryptedMessage> {
        self.queues
            .entry(operator.clone())
            .or_default()
            .drain(..)
            .collect()
    }

    pub fn pending_count(&self, operator: &OperatorId) -> usize {
        self.queues.get(operator).map_or(0, |q| q.len())
    }
}

impl Default for OperatorMessageBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Top-level multi-operator collaboration manager.
#[derive(Debug)]
pub struct MultiOperatorManager {
    pub operators: HashMap<OperatorId, Operator>,
    pub sessions: HashMap<String, SharedSession>,
    pub tasks: Vec<OperatorTask>,
    pub conflicts: ConflictManager,
    pub audit_log: OperatorAuditLog,
    pub message_bus: OperatorMessageBus,
}

impl MultiOperatorManager {
    pub fn new(lock_ttl: Duration) -> Self {
        Self {
            operators: HashMap::new(),
            sessions: HashMap::new(),
            tasks: Vec::new(),
            conflicts: ConflictManager::new(lock_ttl),
            audit_log: OperatorAuditLog::new(),
            message_bus: OperatorMessageBus::new(),
        }
    }

    pub fn register_operator(
        &mut self,
        id: OperatorId,
        display_name: String,
        role: OperatorRole,
        public_key: Vec<u8>,
    ) -> bool {
        if self.operators.contains_key(&id) {
            return false;
        }
        let now = current_timestamp_ms();
        self.operators.insert(
            id.clone(),
            Operator {
                id: id.clone(),
                display_name,
                role,
                public_key,
                registered_at: now,
                last_active: now,
                active_session: None,
            },
        );
        self.audit_log.append(
            id,
            String::new(),
            OperatorAction::Login,
            "operator registered".to_string(),
        );
        true
    }

    pub fn create_session(
        &mut self,
        creator: &OperatorId,
        session_id: String,
        target_url: String,
        description: String,
    ) -> Result<(), String> {
        let op = self.operators.get(creator).ok_or("operator not found")?;
        if !op.role.can_execute_tasks() {
            return Err("insufficient permissions".to_string());
        }
        let session =
            SharedSession::new(session_id.clone(), creator.clone(), target_url, description);
        self.sessions.insert(session_id.clone(), session);
        self.audit_log.append(
            creator.clone(),
            session_id,
            OperatorAction::SessionCreated,
            "session created".to_string(),
        );
        Ok(())
    }

    pub fn join_session(&mut self, operator: &OperatorId, session_id: &str) -> Result<(), String> {
        if !self.operators.contains_key(operator) {
            return Err("operator not found".to_string());
        }
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or("session not found")?;
        session.join(operator.clone());
        self.audit_log.append(
            operator.clone(),
            session_id.to_string(),
            OperatorAction::SessionJoined,
            "joined session".to_string(),
        );
        Ok(())
    }

    pub fn assign_task(
        &mut self,
        assigner: &OperatorId,
        assignee: Option<OperatorId>,
        session_id: &str,
        task_id: String,
        description: String,
        target_endpoint: Option<String>,
    ) -> Result<(), String> {
        let op = self.operators.get(assigner).ok_or("assigner not found")?;
        if !op.role.can_execute_tasks() {
            return Err("insufficient permissions".to_string());
        }
        if let Some(ref endpoint) = target_endpoint {
            self.conflicts
                .acquire_lock(endpoint, assigner.clone())
                .map_err(|e| format!("{}", e))?;
        }
        let task = OperatorTask {
            task_id: task_id.clone(),
            session_id: session_id.to_string(),
            assigned_to: assignee.clone(),
            assigned_by: assigner.clone(),
            description,
            target_endpoint,
            status: if assignee.is_some() {
                TaskStatus::Assigned
            } else {
                TaskStatus::Pending
            },
            created_at: current_timestamp_ms(),
            completed_at: None,
        };
        self.tasks.push(task);
        self.audit_log.append(
            assigner.clone(),
            session_id.to_string(),
            OperatorAction::TaskAssigned,
            format!("task {} assigned", task_id),
        );
        Ok(())
    }

    pub fn complete_task(&mut self, operator: &OperatorId, task_id: &str) -> Result<(), String> {
        let task = self
            .tasks
            .iter_mut()
            .find(|t| t.task_id == task_id)
            .ok_or("task not found")?;
        if task.assigned_to.as_ref() != Some(operator) && &task.assigned_by != operator {
            return Err("not authorized for this task".to_string());
        }
        task.status = TaskStatus::Completed;
        task.completed_at = Some(current_timestamp_ms());
        if let Some(ref endpoint) = task.target_endpoint {
            let _ = self.conflicts.release_lock(endpoint, operator);
        }
        self.audit_log.append(
            operator.clone(),
            task.session_id.clone(),
            OperatorAction::TaskCompleted,
            format!("task {} completed", task_id),
        );
        Ok(())
    }

    pub fn operator_count(&self) -> usize {
        self.operators.len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn pending_tasks(&self) -> Vec<&OperatorTask> {
        self.tasks
            .iter()
            .filter(|t| matches!(t.status, TaskStatus::Pending | TaskStatus::Assigned))
            .collect()
    }
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
