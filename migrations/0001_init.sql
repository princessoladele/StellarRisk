-- StellarRisk core schema (SQLite).
-- Append-only tables (audit_log, alert_decisions) never receive UPDATE/DELETE from the
-- application layer; only INSERT. See crates/audit and crates/alerts.

CREATE TABLE IF NOT EXISTS investigators (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'investigator', 'admin')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flagged_accounts (
    account_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    added_by TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    tx_id TEXT PRIMARY KEY,
    ledger INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    source_account TEXT NOT NULL,
    fee_charged INTEGER NOT NULL,
    memo TEXT,
    operation_count INTEGER NOT NULL,
    successful INTEGER NOT NULL,
    movements_json TEXT NOT NULL,
    contract_ids_json TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_transactions_source_created
    ON transactions (source_account, created_at);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    -- Not a foreign key to transactions: an alert must be creatable from a rules-engine
    -- evaluation even in flows (tests, replay) where the source transaction row hasn't
    -- been persisted separately.
    tx_id TEXT NOT NULL,
    accounts_json TEXT NOT NULL,
    assets_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    triggered_rules_json TEXT NOT NULL,
    score REAL NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    ai_status_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_tx ON alerts (tx_id);

-- Append-only: one row per investigator decision. `alerts.status` is a denormalized
-- projection of the most recent row here, updated in the same transaction as the
-- insert — never mutated independently, and never the row that gets edited.
CREATE TABLE IF NOT EXISTS alert_decisions (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES alerts (id),
    investigator_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    rationale TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alert_decisions_alert ON alert_decisions (alert_id);

-- Append-only, hash-chained audit trail. Sequence is a single global chain across the
-- whole system so the full history can be verified end-to-end.
CREATE TABLE IF NOT EXISTS audit_log (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    alert_id TEXT,
    tx_id TEXT,
    event_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_alert ON audit_log (alert_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_tx ON audit_log (tx_id);

-- Transactions that repeatedly failed ingestion/normalization/evaluation and were set
-- aside rather than silently dropped.
CREATE TABLE IF NOT EXISTS ingestion_dead_letter (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    raw_payload TEXT NOT NULL,
    error TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    first_failed_at TEXT NOT NULL,
    last_failed_at TEXT NOT NULL
);

-- Ingestion cursor bookkeeping, one row per source, so polling resumes where it left off
-- across restarts instead of re-processing or skipping transactions.
CREATE TABLE IF NOT EXISTS ingestion_cursors (
    source TEXT PRIMARY KEY,
    cursor TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
