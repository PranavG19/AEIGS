#[cfg(test)]
mod tests {
    use crate::edge_store::EdgeStore;
    use aegis_protocol::edge::EdgeLabel;
    use aegis_protocol::operation::ModuleIdentifier;

    fn make_store_with_edges() -> EdgeStore {
        let mut store = EdgeStore::new();
        store.insert(
            0,
            1,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            1,
        );
        store.insert(
            0,
            2,
            EdgeLabel::Reads,
            0.5,
            ModuleIdentifier::PassiveRecon,
            2,
        );
        store.insert(
            1,
            2,
            EdgeLabel::Writes,
            0.8,
            ModuleIdentifier::Enumeration,
            1,
        );
        store
    }

    #[test]
    fn insert_and_retrieve_edge() {
        let mut store = EdgeStore::new();
        let id = store.insert(
            0,
            1,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            1,
        );

        let edge = store.get(id).unwrap();
        assert_eq!(edge.id, 0);
        assert_eq!(edge.source_node_id, 0);
        assert_eq!(edge.target_node_id, 1);
        assert_eq!(edge.label, EdgeLabel::Calls);
        assert!((edge.weight - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sequential_edge_id_assignment() {
        let mut store = EdgeStore::new();
        let id0 = store.insert(
            0,
            1,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            1,
        );
        let id1 = store.insert(
            1,
            2,
            EdgeLabel::Reads,
            0.5,
            ModuleIdentifier::PassiveRecon,
            2,
        );

        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
    }

    #[test]
    fn outgoing_edges_correct() {
        let store = make_store_with_edges();

        let outgoing_0 = store.outgoing_edges(0);
        assert_eq!(outgoing_0.len(), 2);

        let outgoing_1 = store.outgoing_edges(1);
        assert_eq!(outgoing_1.len(), 1);
        assert_eq!(store.get(outgoing_1[0]).unwrap().target_node_id, 2);
    }

    #[test]
    fn outgoing_edges_sorted_by_target() {
        let store = make_store_with_edges();

        let outgoing_0 = store.outgoing_edges(0);
        let targets: Vec<u64> = outgoing_0
            .iter()
            .map(|eid| store.get(*eid).unwrap().target_node_id)
            .collect();

        let mut sorted_targets = targets.clone();
        sorted_targets.sort();
        assert_eq!(targets, sorted_targets);
    }

    #[test]
    fn incoming_edges_correct() {
        let store = make_store_with_edges();

        let incoming_2 = store.incoming_edges(2);
        assert_eq!(incoming_2.len(), 2);

        let incoming_0 = store.incoming_edges(0);
        assert!(incoming_0.is_empty());
    }

    #[test]
    fn nonexistent_edge_returns_none() {
        let store = EdgeStore::new();
        assert!(store.get(0).is_none());
        assert!(store.get(999).is_none());
    }

    #[test]
    fn nonexistent_node_adjacency_returns_empty() {
        let store = EdgeStore::new();
        assert!(store.outgoing_edges(999).is_empty());
        assert!(store.incoming_edges(999).is_empty());
    }

    #[test]
    fn count_tracks_insertions() {
        let store = make_store_with_edges();
        assert_eq!(store.count(), 3);
    }

    #[test]
    fn update_weight_modifies_edge() {
        let mut store = EdgeStore::new();
        let id = store.insert(
            0,
            1,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            1,
        );

        assert!(store.update_weight(id, 5.0));
        assert!((store.get(id).unwrap().weight - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn update_weight_nonexistent_returns_false() {
        let mut store = EdgeStore::new();
        assert!(!store.update_weight(999, 5.0));
    }

    #[test]
    fn iter_yields_all_edges() {
        let store = make_store_with_edges();
        let ids: Vec<u64> = store.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }
}

#[cfg(test)]
mod proptests {
    use crate::edge_store::EdgeStore;
    use aegis_protocol::edge::EdgeLabel;
    use aegis_protocol::operation::ModuleIdentifier;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn adjacency_consistency(
            edges in proptest::collection::vec((0u64..10, 0u64..10), 1..20)
        ) {
            let mut store = EdgeStore::new();
            for (src, tgt) in &edges {
                store.insert(*src, *tgt, EdgeLabel::Calls, 1.0, ModuleIdentifier::PassiveRecon, 0);
            }

            for (src, _) in &edges {
                let outgoing = store.outgoing_edges(*src);
                for eid in outgoing {
                    let edge = store.get(*eid).unwrap();
                    prop_assert_eq!(edge.source_node_id, *src);
                }
            }
        }
    }
}
