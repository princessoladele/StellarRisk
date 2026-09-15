#![no_std]
//! DecisionAnchor: a minimal Soroban contract that anchors a *commitment* to an
//! investigator's final decision on a fraud alert — never the alert, the transaction
//! detail, the AI advisory, or any other investigation content. On-chain state is
//! exactly: `hash(alert_id) -> (decision_hash, timestamp)`. Anyone can verify that a
//! specific off-chain decision record (whose hash they can recompute) matches what was
//! anchored, without the chain ever holding sensitive investigation data.
//!
//! Writing an anchor requires the contract admin's authorization. A later decision on
//! the same alert overwrites the anchor for that alert — mirroring the off-chain rule
//! that a new decision doesn't erase history (the full history lives in the append-only
//! audit log off-chain; the chain only ever needs to reflect the *current* decision
//! commitment for verification).

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, BytesN, Env};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Anchor {
    pub decision_hash: BytesN<32>,
    pub timestamp: u64,
}

#[contracttype]
enum DataKey {
    Admin,
    Anchor(BytesN<32>),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum AnchorError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
}

#[contract]
pub struct DecisionAnchorContract;

#[contractimpl]
impl DecisionAnchorContract {
    /// One-time setup: sets the admin account authorized to write anchors. Must be
    /// called once before `anchor`.
    pub fn initialize(env: Env, admin: Address) -> Result<(), AnchorError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(AnchorError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    /// Anchors (or replaces) the decision-hash commitment for `alert_id_hash`. Requires
    /// the admin's authorization — only the risk system's own signing identity can
    /// write, so the chain can't be anchored with commitments from anyone else.
    pub fn anchor(env: Env, alert_id_hash: BytesN<32>, decision_hash: BytesN<32>) -> Result<u64, AnchorError> {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).ok_or(AnchorError::NotInitialized)?;
        admin.require_auth();

        let timestamp = env.ledger().timestamp();
        let anchor = Anchor { decision_hash, timestamp };
        env.storage().persistent().set(&DataKey::Anchor(alert_id_hash), &anchor);
        Ok(timestamp)
    }

    /// Reads back the current commitment for an alert, if one has been anchored.
    pub fn get_anchor(env: Env, alert_id_hash: BytesN<32>) -> Option<Anchor> {
        env.storage().persistent().get(&DataKey::Anchor(alert_id_hash))
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, BytesN, Env};

    use super::*;

    fn setup() -> (Env, DecisionAnchorContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(DecisionAnchorContract, ());
        let client = DecisionAnchorContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, client, admin)
    }

    #[test]
    fn anchors_and_reads_back_a_decision_commitment() {
        let (env, client, _admin) = setup();
        let alert_id_hash = BytesN::from_array(&env, &[1u8; 32]);
        let decision_hash = BytesN::from_array(&env, &[2u8; 32]);

        let ts = client.anchor(&alert_id_hash, &decision_hash);
        let stored = client.get_anchor(&alert_id_hash).unwrap();
        assert_eq!(stored.decision_hash, decision_hash);
        assert_eq!(stored.timestamp, ts);
    }

    #[test]
    fn a_later_decision_overwrites_the_anchor_for_the_same_alert() {
        let (env, client, _admin) = setup();
        let alert_id_hash = BytesN::from_array(&env, &[9u8; 32]);
        let first = BytesN::from_array(&env, &[1u8; 32]);
        let second = BytesN::from_array(&env, &[2u8; 32]);

        client.anchor(&alert_id_hash, &first);
        client.anchor(&alert_id_hash, &second);

        let stored = client.get_anchor(&alert_id_hash).unwrap();
        assert_eq!(stored.decision_hash, second, "the anchor reflects the current decision, matching the off-chain status");
    }

    #[test]
    fn unanchored_alert_returns_none() {
        let (env, client, _admin) = setup();
        let alert_id_hash = BytesN::from_array(&env, &[7u8; 32]);
        assert!(client.get_anchor(&alert_id_hash).is_none());
    }

    #[test]
    fn double_initialize_fails() {
        let (_env, client, admin) = setup();
        let result = client.try_initialize(&admin);
        assert!(result.is_err());
    }
}
