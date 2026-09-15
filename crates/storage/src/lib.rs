//! Sqlite-backed persistence. Implements the storage-agnostic `AlertStore` (from
//! `alerts`) and `AuditStore` (from `audit`) traits, plus concrete repositories for
//! transactions, flagged accounts, investigators, and ingestion bookkeeping that don't
//! have their own crate-level trait boundary.

pub mod alert_store;
pub mod audit_store;
pub mod db;
pub mod error;
pub mod flagged_accounts_repo;
pub mod ingestion_repo;
pub mod investigator_repo;
pub mod tx_repo;

pub use alert_store::SqliteAlertStore;
pub use audit_store::SqliteAuditStore;
pub use db::connect;
pub use flagged_accounts_repo::FlaggedAccountRepository;
pub use ingestion_repo::{DeadLetter, IngestionRepository};
pub use investigator_repo::{InvestigatorRepository, InvestigatorWithHash};
pub use tx_repo::TransactionRepository;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alerts::{AlertService, NewAlert};
    use chrono::{Duration, Utc};
    use domain::{Asset, AssetMovement, Decision, NormalizedTransaction, Role, Severity};

    use super::*;

    async fn test_pool() -> sqlx::SqlitePool {
        connect("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn migrations_and_round_trip_alert_and_audit() {
        let pool = test_pool().await;
        let alert_store: Arc<dyn alerts::AlertStore> = Arc::new(SqliteAlertStore::new(pool.clone()));
        let audit_store: Arc<dyn audit::AuditStore> = Arc::new(SqliteAuditStore::new(pool.clone()));
        let service = AlertService::new(alert_store, audit_store.clone());

        let alert = service
            .create_alert(NewAlert {
                tx_id: "tx1".into(),
                accounts: vec!["GALICE".into()],
                assets: vec![Asset::native()],
                triggered_rules: vec![],
                score: 70.0,
                severity: Severity::High,
            })
            .await
            .unwrap();

        let reloaded = service.get(alert.id).await.unwrap().unwrap();
        assert_eq!(reloaded.tx_id, "tx1");

        service.submit_decision(alert.id, "inv-1", Decision::Escalated, "needs senior review".into()).await.unwrap();
        let after = service.get(alert.id).await.unwrap().unwrap();
        assert_eq!(after.status, domain::AlertStatus::Escalated);

        let verification = audit_store.verify_chain().await.unwrap();
        assert!(verification.valid);
        assert!(verification.records_checked >= 2);
    }

    #[tokio::test]
    async fn transaction_repository_round_trip_and_history() {
        let pool = test_pool().await;
        let repo = TransactionRepository::new(pool);

        let now = Utc::now();
        for i in 0..3 {
            let tx = NormalizedTransaction {
                tx_id: format!("tx-{i}"),
                ledger: 1,
                created_at: now - Duration::seconds(10 * i),
                source_account: "GALICE".into(),
                fee_charged: 100,
                memo: None,
                operation_count: 1,
                successful: true,
                movements: vec![AssetMovement { asset: Asset::native(), from: "GALICE".into(), to: "GBOB".into(), amount: "50".parse().unwrap() }],
                contract_ids: vec![],
            };
            repo.save(&tx).await.unwrap();
        }

        let fetched = repo.get("tx-0").await.unwrap().unwrap();
        assert_eq!(fetched.source_account, "GALICE");

        let history = repo.build_account_history("GALICE", now, Duration::minutes(5), Duration::hours(24)).await.unwrap();
        assert_eq!(history.recent_transactions.len(), 3);
        assert!(history.known_assets.contains("native"));
    }

    #[tokio::test]
    async fn investigator_repository_round_trip() {
        let pool = test_pool().await;
        let repo = InvestigatorRepository::new(pool);
        repo.create("alice", "hash123", Role::Investigator).await.unwrap();
        let found = repo.find_by_username("alice").await.unwrap().unwrap();
        assert_eq!(found.investigator.role, Role::Investigator);
        assert_eq!(found.password_hash, "hash123");
        assert!(repo.find_by_username("nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn ingestion_dead_letter_and_cursor() {
        let pool = test_pool().await;
        let repo = IngestionRepository::new(pool);
        assert!(repo.get_cursor("horizon").await.unwrap().is_none());
        repo.set_cursor("horizon", "cursor-1").await.unwrap();
        assert_eq!(repo.get_cursor("horizon").await.unwrap().unwrap(), "cursor-1");

        repo.add_dead_letter("horizon", "{}", "normalize failed").await.unwrap();
        let letters = repo.list_dead_letters(10).await.unwrap();
        assert_eq!(letters.len(), 1);
        assert_eq!(letters[0].error, "normalize failed");
    }
}
