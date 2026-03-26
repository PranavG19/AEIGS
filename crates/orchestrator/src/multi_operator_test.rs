#[cfg(test)]
mod tests {
    use crate::multi_operator::*;
    use std::time::Duration;

    fn admin_id() -> OperatorId {
        OperatorId("admin-01".to_string())
    }

    fn op_id(name: &str) -> OperatorId {
        OperatorId(name.to_string())
    }

    fn make_manager() -> MultiOperatorManager {
        MultiOperatorManager::new(Duration::from_secs(300))
    }

    #[test]
    fn test_operator_role_permissions() {
        assert!(OperatorRole::Admin.can_execute_tasks());
        assert!(OperatorRole::Admin.can_manage_operators());
        assert!(OperatorRole::Admin.can_modify_config());
        assert!(OperatorRole::Operator.can_execute_tasks());
        assert!(!OperatorRole::Operator.can_manage_operators());
        assert!(OperatorRole::Observer.can_view_findings());
        assert!(!OperatorRole::Observer.can_execute_tasks());
    }

    #[test]
    fn test_operator_role_display() {
        assert_eq!(format!("{}", OperatorRole::Admin), "Admin");
        assert_eq!(format!("{}", OperatorRole::Operator), "Operator");
        assert_eq!(format!("{}", OperatorRole::Observer), "Observer");
    }

    #[test]
    fn test_register_operator() {
        let mut mgr = make_manager();
        assert!(mgr.register_operator(
            admin_id(),
            "Root Admin".to_string(),
            OperatorRole::Admin,
            vec![1, 2, 3],
        ));
        assert_eq!(mgr.operator_count(), 1);
        assert!(!mgr.register_operator(admin_id(), "Dup".to_string(), OperatorRole::Admin, vec![],));
    }

    #[test]
    fn test_create_and_join_session() {
        let mut mgr = make_manager();
        mgr.register_operator(admin_id(), "Admin".to_string(), OperatorRole::Admin, vec![]);
        mgr.register_operator(
            op_id("op-1"),
            "Op One".to_string(),
            OperatorRole::Operator,
            vec![],
        );
        mgr.create_session(
            &admin_id(),
            "sess-1".to_string(),
            "https://target.local".to_string(),
            "pentest engagement".to_string(),
        )
        .unwrap();
        assert_eq!(mgr.session_count(), 1);
        mgr.join_session(&op_id("op-1"), "sess-1").unwrap();
        let sess = mgr.sessions.get("sess-1").unwrap();
        assert_eq!(sess.participant_count(), 2);
    }

    #[test]
    fn test_observer_cannot_create_session() {
        let mut mgr = make_manager();
        mgr.register_operator(
            op_id("obs"),
            "Observer".to_string(),
            OperatorRole::Observer,
            vec![],
        );
        let result = mgr.create_session(
            &op_id("obs"),
            "sess-1".to_string(),
            "https://target.local".to_string(),
            "should fail".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_task_assignment_and_completion() {
        let mut mgr = make_manager();
        mgr.register_operator(admin_id(), "Admin".to_string(), OperatorRole::Admin, vec![]);
        mgr.register_operator(
            op_id("op-1"),
            "Op".to_string(),
            OperatorRole::Operator,
            vec![],
        );
        mgr.create_session(
            &admin_id(),
            "sess-1".to_string(),
            "https://target.local".to_string(),
            "test".to_string(),
        )
        .unwrap();
        mgr.assign_task(
            &admin_id(),
            Some(op_id("op-1")),
            "sess-1",
            "task-1".to_string(),
            "fuzz /api/login".to_string(),
            Some("/api/login".to_string()),
        )
        .unwrap();
        assert_eq!(mgr.pending_tasks().len(), 1);
        assert_eq!(mgr.pending_tasks()[0].status, TaskStatus::Assigned);
        mgr.complete_task(&op_id("op-1"), "task-1").unwrap();
        assert_eq!(mgr.pending_tasks().len(), 0);
    }

    #[test]
    fn test_conflict_prevention() {
        let mut mgr = make_manager();
        mgr.register_operator(admin_id(), "Admin".to_string(), OperatorRole::Admin, vec![]);
        mgr.register_operator(
            op_id("op-1"),
            "Op1".to_string(),
            OperatorRole::Operator,
            vec![],
        );
        mgr.create_session(
            &admin_id(),
            "sess-1".to_string(),
            "https://target.local".to_string(),
            "test".to_string(),
        )
        .unwrap();
        mgr.assign_task(
            &admin_id(),
            Some(op_id("op-1")),
            "sess-1",
            "task-1".to_string(),
            "scan endpoint".to_string(),
            Some("/api/users".to_string()),
        )
        .unwrap();
        let conflict = mgr.assign_task(
            &op_id("op-1"),
            None,
            "sess-1",
            "task-2".to_string(),
            "also scan endpoint".to_string(),
            Some("/api/users".to_string()),
        );
        assert!(conflict.is_err());
    }

    #[test]
    fn test_conflict_manager_lock_lifecycle() {
        let mut cm = ConflictManager::new(Duration::from_secs(60));
        let op = OperatorId("op-a".to_string());
        cm.acquire_lock("/api/login", op.clone()).unwrap();
        assert!(cm.is_locked("/api/login"));
        assert_eq!(cm.active_lock_count(), 1);
        cm.release_lock("/api/login", &op).unwrap();
        assert!(!cm.is_locked("/api/login"));
    }

    #[test]
    fn test_conflict_manager_wrong_owner_release() {
        let mut cm = ConflictManager::new(Duration::from_secs(60));
        let op_a = OperatorId("op-a".to_string());
        let op_b = OperatorId("op-b".to_string());
        cm.acquire_lock("/api/data", op_a).unwrap();
        let result = cm.release_lock("/api/data", &op_b);
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_log_attribution() {
        let mut mgr = make_manager();
        mgr.register_operator(admin_id(), "Admin".to_string(), OperatorRole::Admin, vec![]);
        mgr.register_operator(
            op_id("op-1"),
            "Op".to_string(),
            OperatorRole::Operator,
            vec![],
        );
        mgr.create_session(
            &admin_id(),
            "sess-1".to_string(),
            "https://t.local".to_string(),
            "test".to_string(),
        )
        .unwrap();
        mgr.join_session(&op_id("op-1"), "sess-1").unwrap();
        let admin_entries = mgr.audit_log.entries_by_operator(&admin_id());
        assert!(admin_entries.len() >= 2); // register + create session
        let session_entries = mgr.audit_log.entries_by_session("sess-1");
        assert!(session_entries.len() >= 2); // create + join
    }

    #[test]
    fn test_message_bus_send_receive() {
        let mut bus = OperatorMessageBus::new();
        let from = OperatorId("sender".to_string());
        let to = OperatorId("receiver".to_string());
        bus.send(EncryptedMessage {
            from: from.clone(),
            to: to.clone(),
            ciphertext: vec![0xDE, 0xAD],
            nonce: vec![1, 2, 3],
            timestamp_ms: 1000,
        });
        bus.send(EncryptedMessage {
            from: from.clone(),
            to: to.clone(),
            ciphertext: vec![0xBE, 0xEF],
            nonce: vec![4, 5, 6],
            timestamp_ms: 2000,
        });
        assert_eq!(bus.pending_count(&to), 2);
        let msgs = bus.receive(&to);
        assert_eq!(msgs.len(), 2);
        assert_eq!(bus.pending_count(&to), 0);
    }

    #[test]
    fn test_shared_session_leave() {
        let mut session = SharedSession::new(
            "s1".to_string(),
            OperatorId("creator".to_string()),
            "https://t.local".to_string(),
            "test".to_string(),
        );
        session.join(OperatorId("joiner".to_string()));
        assert_eq!(session.participant_count(), 2);
        session.leave(&OperatorId("joiner".to_string()));
        assert_eq!(session.participant_count(), 1);
    }

    #[test]
    fn test_operator_action_display() {
        assert_eq!(format!("{}", OperatorAction::Login), "login");
        assert_eq!(format!("{}", OperatorAction::TaskAssigned), "task_assigned");
        assert_eq!(
            format!("{}", OperatorAction::CommandExecuted),
            "command_executed"
        );
    }

    #[test]
    fn test_conflict_error_display() {
        let err = ConflictError::ResourceLocked {
            resource: "/api/test".to_string(),
            held_by: OperatorId("op-x".to_string()),
        };
        assert!(format!("{}", err).contains("/api/test"));
        assert!(format!("{}", err).contains("op-x"));
    }

    #[test]
    fn test_task_status_transitions() {
        let mut mgr = make_manager();
        mgr.register_operator(admin_id(), "Admin".to_string(), OperatorRole::Admin, vec![]);
        mgr.create_session(
            &admin_id(),
            "sess-1".to_string(),
            "https://t.local".to_string(),
            "t".to_string(),
        )
        .unwrap();
        mgr.assign_task(
            &admin_id(),
            None,
            "sess-1",
            "unassigned-task".to_string(),
            "unassigned".to_string(),
            None,
        )
        .unwrap();
        let task = mgr
            .tasks
            .iter()
            .find(|t| t.task_id == "unassigned-task")
            .unwrap();
        assert_eq!(task.status, TaskStatus::Pending);
    }
}
