#[cfg(test)]
mod tests {
    use crate::node_store::NodeStore;
    use aegis_protocol::node::NodeType;
    use std::collections::HashMap;

    fn empty_props() -> HashMap<String, String> {
        HashMap::new()
    }

    fn props(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn insert_and_retrieve_single_node() {
        let mut store = NodeStore::new();
        let id = store.insert(NodeType::Endpoint, props(&[("path", "/api/users")]));
        let node = store.get(id).unwrap();

        assert_eq!(node.id, 0);
        assert_eq!(node.node_type, NodeType::Endpoint);
        assert_eq!(node.properties.get("path").unwrap(), "/api/users");
    }

    #[test]
    fn sequential_id_assignment() {
        let mut store = NodeStore::new();
        let id0 = store.insert(NodeType::Endpoint, empty_props());
        let id1 = store.insert(NodeType::Function, empty_props());
        let id2 = store.insert(NodeType::DataStore, empty_props());

        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = NodeStore::new();
        assert!(store.get(0).is_none());
        assert!(store.get(999).is_none());
    }

    #[test]
    fn count_tracks_insertions() {
        let mut store = NodeStore::new();
        assert_eq!(store.count(), 0);

        store.insert(NodeType::Service, empty_props());
        assert_eq!(store.count(), 1);

        store.insert(NodeType::User, empty_props());
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn get_mut_modifies_node_properties() {
        let mut store = NodeStore::new();
        store.insert(NodeType::Config, empty_props());

        let node = store.get_mut(0).unwrap();
        node.properties
            .insert("key".to_string(), "value".to_string());

        let node = store.get(0).unwrap();
        assert_eq!(node.properties.get("key").unwrap(), "value");
    }

    #[test]
    fn iter_yields_all_nodes() {
        let mut store = NodeStore::new();
        store.insert(NodeType::Endpoint, empty_props());
        store.insert(NodeType::Function, empty_props());
        store.insert(NodeType::DataStore, empty_props());

        let ids: Vec<u64> = store.iter().map(|n| n.id).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn nodes_by_type_filters_correctly() {
        let mut store = NodeStore::new();
        store.insert(NodeType::Endpoint, empty_props());
        store.insert(NodeType::Function, empty_props());
        store.insert(NodeType::Endpoint, empty_props());
        store.insert(NodeType::DataStore, empty_props());

        let endpoints = store.nodes_by_type(NodeType::Endpoint);
        assert_eq!(endpoints, &[0, 2]);

        let functions = store.nodes_by_type(NodeType::Function);
        assert_eq!(functions, &[1]);

        let roles = store.nodes_by_type(NodeType::Role);
        assert!(roles.is_empty());
    }

    #[test]
    fn default_creates_empty_store() {
        let store = NodeStore::default();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn snapshot_restore_roundtrip() {
        let mut store = NodeStore::new();
        store.insert(NodeType::Endpoint, props(&[("path", "/api/users")]));
        store.insert(NodeType::Function, props(&[("name", "handle_request")]));
        store.insert(NodeType::Endpoint, empty_props());

        let bytes = store.snapshot();
        let restored = NodeStore::restore(&bytes).unwrap();

        assert_eq!(restored.count(), 3);
        let n0 = restored.get(0).unwrap();
        assert_eq!(n0.node_type, NodeType::Endpoint);
        assert_eq!(n0.properties.get("path").unwrap(), "/api/users");
        let n1 = restored.get(1).unwrap();
        assert_eq!(n1.node_type, NodeType::Function);
        assert_eq!(n1.properties.get("name").unwrap(), "handle_request");
        assert_eq!(restored.nodes_by_type(NodeType::Endpoint), &[0, 2]);
        assert_eq!(restored.nodes_by_type(NodeType::Function), &[1]);
    }

    #[test]
    fn restore_corrupted_data_returns_error() {
        let result = NodeStore::restore(b"not valid json{{{");
        assert!(result.is_err());
    }

    #[test]
    fn empty_store_snapshot_restore() {
        let store = NodeStore::new();
        let bytes = store.snapshot();
        let restored = NodeStore::restore(&bytes).unwrap();
        assert_eq!(restored.count(), 0);
        assert!(restored.nodes_by_type(NodeType::Endpoint).is_empty());
    }
}

#[cfg(test)]
mod proptests {
    use crate::node_store::NodeStore;
    use aegis_protocol::node::NodeType;
    use proptest::prelude::*;
    use std::collections::HashMap;

    fn arbitrary_node_type() -> impl Strategy<Value = NodeType> {
        prop_oneof![
            Just(NodeType::Endpoint),
            Just(NodeType::Function),
            Just(NodeType::DataStore),
            Just(NodeType::Role),
            Just(NodeType::Dependency),
            Just(NodeType::Config),
            Just(NodeType::User),
            Just(NodeType::Service),
        ]
    }

    proptest! {
        #[test]
        fn insert_get_roundtrip(node_type in arbitrary_node_type(), key in "[a-z]{1,10}", value in "[a-z]{1,10}") {
            let mut store = NodeStore::new();
            let mut props = HashMap::new();
            props.insert(key.clone(), value.clone());

            let id = store.insert(node_type, props);
            let node = store.get(id).unwrap();

            prop_assert_eq!(node.id, id);
            prop_assert_eq!(node.node_type, node_type);
            prop_assert_eq!(node.properties.get(&key).unwrap(), &value);
        }

        #[test]
        fn count_equals_insertions(count in 0usize..100) {
            let mut store = NodeStore::new();
            for _ in 0..count {
                store.insert(NodeType::Endpoint, HashMap::new());
            }
            prop_assert_eq!(store.count(), count);
        }
    }
}
