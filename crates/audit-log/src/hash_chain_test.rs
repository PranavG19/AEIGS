#[cfg(test)]
mod tests {
    use crate::hash_chain::{compute_next_hash, genesis_hash, verify_chain, HashChain};

    #[test]
    fn genesis_hash_is_deterministic() {
        let h1 = genesis_hash();
        let h2 = genesis_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn genesis_hash_is_nonzero() {
        let h = genesis_hash();
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn append_produces_different_hash_for_different_data() {
        let mut chain1 = HashChain::new();
        let mut chain2 = HashChain::new();

        let h1 = chain1.append(b"hello");
        let h2 = chain2.append(b"world");

        assert_ne!(h1, h2);
    }

    #[test]
    fn append_produces_same_hash_for_same_data() {
        let mut chain1 = HashChain::new();
        let mut chain2 = HashChain::new();

        let h1 = chain1.append(b"same data");
        let h2 = chain2.append(b"same data");

        assert_eq!(h1, h2);
    }

    #[test]
    fn chain_state_changes_with_each_append() {
        let mut chain = HashChain::new();

        let h1 = chain.append(b"first");
        let h2 = chain.append(b"first");

        assert_ne!(h1, h2);
    }

    #[test]
    fn current_hash_reflects_last_append() {
        let mut chain = HashChain::new();
        let hash = chain.append(b"data");
        assert_eq!(chain.current_hash(), hash);
    }

    #[test]
    fn verify_chain_passes_for_valid_chain() {
        let mut chain = HashChain::new();
        let mut entries = Vec::new();

        for i in 0..10 {
            let data = format!("entry-{i}").into_bytes();
            let hash = chain.append(&data);
            entries.push((hash, data));
        }

        assert!(verify_chain(&entries));
    }

    #[test]
    fn verify_chain_fails_if_entry_modified() {
        let mut chain = HashChain::new();
        let mut entries = Vec::new();

        for i in 0..5 {
            let data = format!("entry-{i}").into_bytes();
            let hash = chain.append(&data);
            entries.push((hash, data));
        }

        entries[2].1 = b"tampered".to_vec();
        assert!(!verify_chain(&entries));
    }

    #[test]
    fn verify_chain_fails_if_entry_removed() {
        let mut chain = HashChain::new();
        let mut entries = Vec::new();

        for i in 0..5 {
            let data = format!("entry-{i}").into_bytes();
            let hash = chain.append(&data);
            entries.push((hash, data));
        }

        entries.remove(2);
        assert!(!verify_chain(&entries));
    }

    #[test]
    fn verify_chain_passes_for_empty() {
        assert!(verify_chain(&[]));
    }

    #[test]
    fn verify_chain_of_100_entries() {
        let mut chain = HashChain::new();
        let mut entries = Vec::new();

        for i in 0..100 {
            let data = format!("log-entry-{i:04}").into_bytes();
            let hash = chain.append(&data);
            entries.push((hash, data));
        }

        assert!(verify_chain(&entries));
    }

    #[test]
    fn compute_next_hash_matches_chain_append() {
        let genesis = genesis_hash();
        let data = b"test data";

        let mut chain = HashChain::new();
        let chain_hash = chain.append(data);

        let computed = compute_next_hash(&genesis, data);
        assert_eq!(chain_hash, computed);
    }

    #[test]
    fn default_chain_starts_at_genesis() {
        let chain = HashChain::default();
        assert_eq!(chain.current_hash(), genesis_hash());
    }
}
