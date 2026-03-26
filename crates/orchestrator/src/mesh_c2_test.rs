#[cfg(test)]
mod tests {
    use crate::mesh_c2::*;
    use std::time::{Duration, Instant};

    fn make_entry(id: u64, addr: &str) -> DhtEntry {
        DhtEntry {
            peer_id: PeerId(id),
            address: addr.to_string(),
            last_seen: Instant::now(),
            latency_ms: 50,
            capabilities: vec!["beacon".to_string()],
        }
    }

    #[test]
    fn test_xor_distance() {
        assert_eq!(xor_distance(PeerId(0b1010), PeerId(0b0110)), 0b1100);
        assert_eq!(xor_distance(PeerId(42), PeerId(42)), 0);
    }

    #[test]
    fn test_peer_id_display() {
        let p = PeerId(255);
        assert!(format!("{}", p).contains("00ff"));
    }

    #[test]
    fn test_kbucket_insert_and_closest() {
        let mut bucket = KBucket::new(3);
        assert!(bucket.insert(make_entry(1, "10.0.0.1:4444")));
        assert!(bucket.insert(make_entry(2, "10.0.0.2:4444")));
        assert!(bucket.insert(make_entry(3, "10.0.0.3:4444")));
        assert!(!bucket.insert(make_entry(4, "10.0.0.4:4444")));
        let closest = bucket.closest(PeerId(1), 2);
        assert_eq!(closest.len(), 2);
        assert_eq!(closest[0].peer_id, PeerId(1));
    }

    #[test]
    fn test_kbucket_update_existing() {
        let mut bucket = KBucket::new(2);
        bucket.insert(make_entry(1, "old"));
        bucket.insert(make_entry(1, "new"));
        assert_eq!(bucket.entries.len(), 1);
        assert_eq!(bucket.entries[0].address, "new");
    }

    #[test]
    fn test_dht_routing_table_insert_and_find() {
        let local = PeerId(0);
        let mut dht = DhtRoutingTable::new(local, 20);
        for i in 1..=10 {
            dht.insert(make_entry(i, &format!("10.0.0.{}:4444", i)));
        }
        assert_eq!(dht.peer_count(), 10);
        let closest = dht.find_closest(PeerId(5), 3);
        assert_eq!(closest.len(), 3);
        assert_eq!(closest[0].peer_id, PeerId(5));
    }

    #[test]
    fn test_onion_route_build_and_peel() {
        let hops = vec![PeerId(1), PeerId(2), PeerId(3)];
        let mut msg = build_onion_route(&hops, b"secret-command", 42);
        assert_eq!(msg.layers.len(), 3);
        assert_eq!(msg.message_id, 42);
        let first = peel_onion_layer(&mut msg).unwrap();
        assert_eq!(first, PeerId(1));
        assert_eq!(msg.layers.len(), 2);
        let second = peel_onion_layer(&mut msg).unwrap();
        assert_eq!(second, PeerId(2));
        let third = peel_onion_layer(&mut msg).unwrap();
        assert_eq!(third, PeerId(3));
        assert!(peel_onion_layer(&mut msg).is_none());
        assert_eq!(msg.final_payload, b"secret-command");
    }

    #[test]
    fn test_message_deduplicator() {
        let mut dedup = MessageDeduplicator::new(3);
        assert!(!dedup.is_duplicate(1));
        assert!(dedup.is_duplicate(1));
        assert!(!dedup.is_duplicate(2));
        assert!(!dedup.is_duplicate(3));
        assert!(!dedup.is_duplicate(4)); // evicts 1
        assert!(!dedup.is_duplicate(1)); // 1 was evicted, not dup
        assert_eq!(dedup.seen_count(), 3);
    }

    #[test]
    fn test_gossip_engine_receive_and_forward() {
        let mut engine = GossipEngine::new(PeerId(0), 2, 100);
        let msg = GossipMessage {
            id: 1,
            origin: PeerId(10),
            msg_type: GossipMessageType::Command,
            payload: b"do-thing".to_vec(),
            ttl: 3,
            timestamp_ms: 1000,
        };
        let neighbors = vec![PeerId(10), PeerId(20), PeerId(30), PeerId(40)];
        let delivered = engine.receive(msg, &neighbors);
        assert!(delivered.is_some());
        let forwards = engine.drain_forwards();
        assert_eq!(forwards.len(), 2);
        assert!(forwards.iter().all(|(_, m)| m.ttl == 2));
    }

    #[test]
    fn test_gossip_dedup_blocks_rebroadcast() {
        let mut engine = GossipEngine::new(PeerId(0), 2, 100);
        let msg = GossipMessage {
            id: 1,
            origin: PeerId(10),
            msg_type: GossipMessageType::Heartbeat,
            payload: vec![],
            ttl: 5,
            timestamp_ms: 1000,
        };
        let neighbors = vec![PeerId(20)];
        assert!(engine.receive(msg.clone(), &neighbors).is_some());
        assert!(engine.receive(msg, &neighbors).is_none());
    }

    #[test]
    fn test_gossip_ttl_zero_no_forward() {
        let mut engine = GossipEngine::new(PeerId(0), 2, 100);
        let msg = GossipMessage {
            id: 99,
            origin: PeerId(5),
            msg_type: GossipMessageType::FindingBroadcast,
            payload: vec![1, 2, 3],
            ttl: 0,
            timestamp_ms: 2000,
        };
        let delivered = engine.receive(msg, &[PeerId(20), PeerId(30)]);
        assert!(delivered.is_some());
        assert!(engine.drain_forwards().is_empty());
    }

    #[test]
    fn test_redundant_router() {
        let mut router = RedundantRouter::new(3);
        let dest = PeerId(100);
        router.add_route(dest, vec![PeerId(1), PeerId(2)]);
        router.add_route(dest, vec![PeerId(3), PeerId(4)]);
        router.add_route(dest, vec![PeerId(1), PeerId(2)]); // dup ignored
        assert_eq!(router.route_count(dest), 2);
        assert!(router.get_route(dest).is_some());
        let alt = router.get_alternate_route(dest, PeerId(1));
        assert!(alt.is_some());
        assert_eq!(alt.unwrap()[0], PeerId(3));
    }

    #[test]
    fn test_peer_health_tracker() {
        let mut tracker = PeerHealthTracker::new(2, 5);
        let peer = PeerId(42);
        tracker.record_success(peer);
        assert_eq!(tracker.get_health(peer), PeerHealth::Healthy);
        tracker.record_failure(peer);
        tracker.record_failure(peer);
        assert_eq!(tracker.get_health(peer), PeerHealth::Degraded);
        for _ in 0..3 {
            tracker.record_failure(peer);
        }
        assert_eq!(tracker.get_health(peer), PeerHealth::Unreachable);
        assert!(!tracker.is_reachable(peer));
        tracker.record_success(peer);
        assert!(tracker.is_reachable(peer));
    }

    #[test]
    fn test_mesh_c2_full_flow() {
        let mut mesh = MeshC2::new(PeerId(0), MeshC2Config::default());
        for i in 1..=5 {
            mesh.register_peer(make_entry(i, &format!("10.0.0.{}:4444", i)));
        }
        assert_eq!(mesh.peer_count(), 5);
        let msg = mesh.send_command(PeerId(3), b"exec-whoami");
        assert!(msg.is_some());
        let onion = msg.unwrap();
        assert!(!onion.layers.is_empty());
    }

    #[test]
    fn test_mesh_c2_broadcast() {
        let mut mesh = MeshC2::new(PeerId(0), MeshC2Config::default());
        for i in 1..=4 {
            mesh.register_peer(make_entry(i, &format!("10.0.0.{}:4444", i)));
        }
        let gossip = GossipMessage {
            id: 7,
            origin: PeerId(0),
            msg_type: GossipMessageType::Command,
            payload: b"broadcast-cmd".to_vec(),
            ttl: 3,
            timestamp_ms: 5000,
        };
        let forwards = mesh.broadcast_gossip(gossip);
        assert!(!forwards.is_empty());
    }

    #[test]
    fn test_mesh_c2_config_default() {
        let cfg = MeshC2Config::default();
        assert_eq!(cfg.k_bucket_size, 20);
        assert_eq!(cfg.gossip_fanout, 3);
        assert_eq!(cfg.default_onion_hops, 3);
        assert_eq!(cfg.beacon_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_send_to_unreachable_peer_reroutes() {
        let mut mesh = MeshC2::new(PeerId(0), MeshC2Config::default());
        mesh.register_peer(make_entry(1, "10.0.0.1:4444"));
        mesh.register_peer(make_entry(2, "10.0.0.2:4444"));
        for _ in 0..10 {
            mesh.health.record_failure(PeerId(1));
        }
        assert!(!mesh.health.is_reachable(PeerId(1)));
        let msg = mesh.send_command(PeerId(99), b"test");
        // Should still route via healthy peers
        if let Some(m) = msg {
            for layer in &m.layers {
                assert_ne!(layer.next_hop, PeerId(1));
            }
        }
    }

    #[test]
    fn test_gossip_message_types() {
        assert_eq!(GossipMessageType::Command, GossipMessageType::Command);
        assert_ne!(GossipMessageType::Command, GossipMessageType::Heartbeat);
        assert_ne!(
            GossipMessageType::PeerAnnounce,
            GossipMessageType::PeerLeave
        );
    }
}
