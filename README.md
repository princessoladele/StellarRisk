# StellarRisk

A production-oriented fraud and anomaly detection triage assistant for the Stellar
ecosystem. It watches Stellar transactions in real time, runs them through a
deterministic, explainable rules engine, opens alerts with an anomaly score, asks an AI
model for an advisory-only investigation writeup, and puts the final decision in the
hands of an authenticated human investigator — with a full, append-only, tamper-evident
audit trail of everything that happened along the way.

> AI can recommend. Only a human can decide. That boundary is enforced in the type
> system, not just the UI — see [The AI/human boundary](#the-aihuman-boundary).

## Architecture

The system is a Cargo workspace of small, single-purpose crates, each owning one layer
of the pipeline:

```
Stellar/Soroban ─▶ ingestion ─▶ rules_engine ─▶ alerts ─▶ ai_advisor
 (Horizon/mock)   (normalize)   (rules+score)  (lifecycle)  (advisory)
                                     │              │            │
                                     └──────────────┼────────────┘
                                                     ▼
                                                   audit
                                          (append-only, hash-chained)
                                                     │
                                                     ▼
                                                    api
                                    (axum HTTP API + investigator dashboard)
                                                     │
                                                     ▼
                                             soroban_anchor (optional)
                                      (on-chain decision-hash commitment)
```

| Crate | Responsibility |
|---|---|
| [`domain`](crates/domain) | Shared types only — transactions, alerts, rules, decisions, audit events, AI advisories. No I/O, no dependency on any other workspace crate. |
| [`storage`](crates/storage) | SQLite (via `sqlx`) persistence: migrations, `SqliteAlertStore`, `SqliteAuditStore`, transaction/history/investigator/flagged-account/ingestion repositories. |
| [`ingestion`](crates/ingestion) | Stellar/Soroban transaction ingestion (layers 1–2). `TransactionSource` trait; `HorizonTransactionSource` (real Horizon REST polling, retry+backoff) and `MockTransactionSource` (demo/tests, no network). Normalizes raw Horizon JSON into `domain::NormalizedTransaction`. |
| [`rules_engine`](crates/rules_engine) | Deterministic fraud rules + anomaly scoring (layers 3–4). `Rule` trait + `RuleRegistry`; six built-in rules; `scoring::score_and_severity`. |
| [`alerts`](crates/alerts) | Alert lifecycle + human review workflow (layers 5, 7). `AlertService::submit_decision` is the *only* function that can change an alert's status. |
| [`ai_advisor`](crates/ai_advisor) | AI investigation assistant (layer 6), strictly advisory. Calls the Anthropic Messages API directly over HTTP; validates/sanitizes the response before it's ever stored. |
| [`audit`](crates/audit) | Append-only, hash-chained audit trail (layer 8). |
| [`soroban_anchor`](crates/soroban_anchor) + [`contract/`](crates/soroban_anchor/contract) | Optional on-chain verification: a minimal Soroban contract that anchors only a *hash* of each decision, never investigation content. |
| [`api`](crates/api) | HTTP API + auth (layer 9) and the server-rendered investigator dashboard (layer 10). Wires every other crate together and runs the background ingestion pipeline. |

Event normalization (raw Horizon JSON → `NormalizedTransaction`) lives inside
`ingestion`; the human review workflow (decision state machine, append-only decision
history) lives inside `alerts`. Both are separated by module, not just by comment, from
their neighboring layers.

### Why this shape

- **`domain` depends on nothing.** Every other crate depends on it, so the vocabulary of
  the system (what's an `Alert`, what's a `Decision`) has exactly one definition.
- **Adding a rule never touches the engine.** `rules_engine::Rule` is a trait; new fraud
  checks are added via `RuleRegistry::register` without modifying `rules_engine`'s own
  code, per the assignment's modularity requirement.
- **`ai_advisor` cannot reach the write path.** It depends only on `domain` — it has no
  dependency on `alerts` or `storage`, so it is *structurally* incapable of writing an
  alert status even if its code tried to.

## Fraud detection flow

1. **Ingest**: `ingestion::TransactionSource::poll()` returns a batch of
   `NormalizedTransaction`s (from Horizon or the demo mock source).
2. **Persist + build history**: `storage::TransactionRepository` saves the transaction
   and builds an `AccountHistory` (recent transactions, a rolling per-hour baseline, and
   known assets for the source account) — this is the *only* input to the rules engine
   beyond the transaction itself, so evaluation stays a pure function of its inputs.
3. **Evaluate**: `rules_engine::evaluate()` runs the registry's rules against
   `(transaction, history, config, now)` and combines any triggers into a 0–100 anomaly
   score and a severity band (Low/Medium/High/Critical). Every trigger carries a
   structured, human-readable `reason` plus `evidence` (the concrete numbers that
   justify it) — nothing is a black box.
4. **Alert**: if anything triggered, `alerts::AlertService::create_alert` opens an
   `Alert` (`status: Open`) and `audit` records `AlertCreated`.
5. **AI advisory (best-effort)**: `ai_advisor::AiAdvisor::investigate()` is called with a
   minimal, purpose-built request (transaction summary, triggered rules + reasons,
   aggregate history stats — not a raw transaction dump). Success or failure, `audit`
   records what happened; failure never blocks the alert.
6. **Human review**: an authenticated investigator inspects the alert, the rule reasons,
   the anomaly score, and the AI advisory (clearly labeled, never auto-applied), then
   calls `AlertService::submit_decision` with one of four decisions. This is recorded as
   a **new**, append-only row — never an edit to a previous decision — and `audit` gets
   an `InvestigatorDecision` event.
7. **Optional on-chain anchor**: `soroban_anchor::DecisionAnchor::anchor_decision`
   best-effort anchors `hash(decision record)` on-chain via the `DecisionAnchorContract`.

### Built-in rules

| Rule | Detects |
|---|---|
| `large_transfer` | A single movement exceeding a configurable per-asset (or default) threshold |
| `velocity` | More than N transactions from an account within a short window |
| `abnormal_frequency` | Transaction rate a large multiple of *that account's own* rolling baseline |
| `flagged_account_interaction` | Source or counterparty is on the flagged-accounts list |
| `unusual_asset_movement` | An asset the account has no prior recorded history moving |
| `operation_count_threshold` | Unusually many operations bundled into one transaction (a generic, configurable-threshold check independent of transfer size) |

All thresholds live in `rules_engine::RulesConfig` / `ScoringConfig` — no rule reads a
magic number from its own source.

## The AI/human boundary

This is the part of the spec the implementation is built to make impossible to violate
by accident, not just by convention:

- **Type-level separation.** `domain::AiAdvisory` has no field that can represent a
  `domain::Decision` or `domain::AlertStatus`. `domain::Decision` is a closed 4-variant
  enum (`Dismissed` / `UnderInvestigation` / `Escalated` / `ConfirmedSuspicious`) with no
  `From<AiAdvisory>` impl anywhere in the codebase.
- **One write path.** `alerts::AlertService::submit_decision(alert_id, investigator_id,
  decision: Decision, rationale)` is the only function, anywhere, that changes
  `Alert::status`. `ai_advisor` has no dependency on `alerts` or `storage` — it *cannot*
  call it, even hypothetically.
- **Untrusted input, validated.** The AI's tool-call response is deserialized into a
  strict schema (`ai_advisor::validate::RawAdvisoryInput`), then every field is
  length-capped, control characters are stripped, `risk_level` is checked against a
  closed vocabulary, and confidence is clamped to `[0, 1]` — see
  `ai_advisor::validate::validate_and_sanitize`. The dashboard also HTML-escapes
  everything independently, as a second, unrelated layer of defense.
  Malformed/refused/unreachable responses become `AiAdvisoryStatus::Unavailable`, never
  a panic or a blocked pipeline.
- **Visibly labeled.** Every advisory carries a fixed disclaimer
  (`domain::AI_ADVISORY_DISCLAIMER`) rendered verbatim, and the dashboard puts AI output
  in a distinct purple "AI Advisory — Recommendation Only" panel next to a separate
  green "Human Decision — Final Authority" panel with the actual decision form.
- **Proven in tests, not just asserted in docs**: `ai_advisor_never_changes_alert_status`
  (`crates/alerts/src/lib.rs`) and `ai_advisory_cannot_be_submitted_as_a_decision`
  (`crates/api/src/lib.rs`, an HTTP-level test that tries to smuggle AI-style free text
  into the decision field and confirms the API rejects anything outside the four closed
  `Decision` variants).

## Audit model

Every alert-affecting event — creation, the AI request payload actually sent, the AI
response received (or why it wasn't), and every investigator decision — is written to
`audit_log` as one closed `AuditEventKind` variant. The store
(`audit::AuditStore`/`storage::SqliteAuditStore`) exposes **append and read only**;
there is no update or delete method anywhere in its API.

Tamper-evidence: each record stores `sha256(prev_hash ∥ canonical_json(record))`, with
`prev_hash` chained from the previous record (`audit::GENESIS_HASH` for the first ever
record). `audit::verify_chain` recomputes every hash and confirms the chain — a `GET
/api/audit/verify` (admin-only) exposes this over HTTP. One subtlety: hashing uses the
*exact stored JSON text*, not a re-serialization of the parsed struct — floating-point
fields (scores, confidence, rates) aren't guaranteed to round-trip byte-for-byte through
a parse-then-reserialize cycle, which would otherwise make verification report spurious
tampering on untouched records (`domain::AuditRecord::event_json`).

A later decision on an alert never overwrites an earlier one: `alert_decisions` is an
append-only table, and `Alert.status` is a denormalized projection of the latest row,
updated in the same transaction as the insert — the full history is always
reconstructable from `alert_decisions` and `audit_log` alone.

## Stellar/Soroban integration

- **Ingestion** (`ingestion::HorizonTransactionSource`) polls the Horizon REST API
  (`GET /transactions`, `GET /transactions/{id}/operations`) directly over HTTP (there
  is no official Horizon Rust SDK maintained for this purpose at the pinned dependency
  set), with cursor persistence (`storage::IngestionRepository`) and exponential-backoff
  retry on transient failures. A single transaction's operations failing to fetch
  doesn't drop the whole batch — it's reported as a `FetchFailure` and routed to the
  ingestion dead-letter table (`ingestion_dead_letter`) instead of being silently lost.
- **Soroban is used for exactly one thing**: anchoring a *commitment* to a final
  decision, never investigation data. `crates/soroban_anchor/contract` is a real,
  independently-tested Soroban contract (`soroban-sdk` 27) storing
  `hash(alert_id) -> (hash(decision_record), timestamp)`. Nothing else about an alert —
  transaction detail, AI advisory, investigator rationale — ever goes on-chain, per the
  requirement that sensitive investigation data stay off-chain.
- Anchoring is **optional and best-effort**: `soroban_anchor::NoopAnchor` is the default
  when no Soroban identity is configured, and `CliSorobanAnchor` (which shells out to the
  official `stellar` CLI rather than hand-rolling XDR transaction building/signing)
  treats any failure as non-fatal and logs it — the human decision is never blocked or
  delayed by chain availability.
- The contract crate is intentionally its own **nested Cargo workspace**
  (`crates/soroban_anchor/contract/Cargo.toml` has its own `[workspace]`) so its
  wasm-only release profile (`panic = "abort"`, LTO, `opt-level = "z"`) never leaks into
  the host application's build.

## Setup

Requirements: Rust (stable), a C compiler (for `libsqlite3-sys`). No external database
or network access is required to build, test, or run in demo mode.

```bash
cp .env.example .env        # adjust as needed; every value has a safe default
cargo build --workspace
cargo test --workspace
cargo run -p api            # binary name: stellarrisk-api
```

On first run, the server seeds one admin investigator from `ADMIN_USERNAME` /
`ADMIN_PASSWORD` (default `admin` / `change-me-immediately` — **change this** for
anything beyond local experimentation) and, since `HORIZON_URL` is unset by default,
runs in **demo mode**: a small built-in set of synthetic transactions (a large transfer,
a velocity burst, a flagged-account interaction) is replayed through the real pipeline
so there's something to see immediately.

Then open `http://127.0.0.1:8080/login`, sign in, and use the dashboard — or drive the
JSON API directly (`POST /api/auth/login` for a bearer token, then the `/api/...`
endpoints below).

To point at real Stellar testnet activity instead of the demo set, set
`HORIZON_URL=https://horizon-testnet.stellar.org` in `.env`.

### Soroban contract

The contract is a separate nested workspace (see above). To build and test it:

```bash
cd crates/soroban_anchor/contract
cargo test                                    # native unit tests, no network needed
rustup target add wasm32v1-none               # first time only
cargo build --release --target wasm32v1-none  # produces the deployable .wasm
```

Deploying it and wiring `SOROBAN_CONTRACT_ID` / `SOROBAN_NETWORK` /
`SOROBAN_SOURCE_ACCOUNT` (plus a configured `stellar` CLI identity) is optional; the
system works fully without it, just without the on-chain anchor step.

## Environment variables

See [`.env.example`](.env.example) for the full annotated list. Summary:

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | SQLite connection string | `sqlite://stellarrisk.db` |
| `BIND_ADDR` | HTTP listen address | `127.0.0.1:8080` |
| `JWT_SECRET` | Session token signing secret | insecure dev default — **override in production** |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Seeded on first run if no investigators exist | `admin` / `change-me-immediately` |
| `HORIZON_URL` | Real Horizon endpoint; unset = demo mode | unset |
| `POLL_INTERVAL_SECS` | Ingestion poll interval | `15` |
| `ANTHROPIC_API_KEY` | Enables AI advisories; unset = advisories disabled, rest of system unaffected | unset |
| `ANTHROPIC_MODEL` | Overrides the default model | `claude-opus-5` |
| `SOROBAN_CONTRACT_ID` / `SOROBAN_NETWORK` / `SOROBAN_SOURCE_ACCOUNT` | Enable on-chain decision anchoring; all three required | unset (anchoring disabled) |
| `RUST_LOG` | `tracing-subscriber` filter | `info` |

## API surface

All JSON endpoints under `/api` require `Authorization: Bearer <token>` (from `POST
/api/auth/login`) except `/api/health` and login itself; `POST /api/alerts/:id/decision`
additionally requires the `investigator` or `admin` role.

| Endpoint | Purpose |
|---|---|
| `POST /api/auth/login` | Exchange credentials for a JWT |
| `GET /api/transactions`, `GET /api/transactions/:tx_id` | Retrieve ingested transactions |
| `POST /api/transactions/ingest` (admin) | Manually ingest a transaction through the full pipeline |
| `POST /api/transactions/:tx_id/evaluate` | Read-only: run the rules engine on demand |
| `GET /api/alerts`, `GET /api/alerts/:id` | Retrieve alerts |
| `GET /api/alerts/:id/ai` | Retrieve the AI investigation context/advisory (read-only) |
| `POST /api/alerts/:id/decision` (investigator/admin) | Record the final decision — the only status-changing endpoint |
| `GET /api/alerts/:id/decisions` | Full decision history for an alert |
| `GET /api/alerts/:id/audit` | Full audit trail for an alert |
| `GET /api/audit/verify` (admin) | Recompute and verify the entire hash chain |

The dashboard (`/dashboard`, `/dashboard/alerts/:id`) is server-rendered HTML using the
same JWT, carried via an `HttpOnly` cookie set at `/login`.

## Investigator dashboard

- **Alert list** (`/dashboard`): severity, status, score, and triggered-rule count for
  every alert.
- **Alert detail** (`/dashboard/alerts/:id`): transaction detail, every triggered rule
  with its reason, the anomaly score, a purple **AI Advisory** panel (or an honest
  "Unavailable" note if the AI service couldn't be reached), a green **Human
  Decision — Final Authority** panel with the decision form (hidden/read-only for the
  `viewer` role), the full decision history, and the raw append-only audit trail.

The color/label split between the AI panel and the human-decision panel is deliberate:
the human-in-the-loop boundary is meant to be obvious at a glance, not just documented.

## Testing strategy

`cargo test --workspace` runs 45 tests with no external services required (Anthropic and
Horizon calls are mocked with `wiremock`; storage tests use an in-process SQLite; the
Soroban contract's 4 tests run separately — see above — against `soroban-sdk`'s native
test `Env`, also with no network).

- **Rules engine** (`rules_engine`, 8 tests): each rule's trigger/no-trigger cases, a
  determinism check (same input → identical output, twice), and a scoring/severity
  table.
- **Anomaly scoring**: covered in the same suite (`scoring_maps_trigger_weights_to_severity_bands`).
- **Alert lifecycle** (`alerts`, 4 tests): status starts `Open`, only `submit_decision`
  changes it, two decisions on one alert both remain in history, AI advisories never
  touch status.
- **AI response validation** (`ai_advisor`, 12 tests): malformed/refused/unreachable
  responses handled without panicking; control characters, `<script` sequences, unknown
  risk levels, and oversized lists are all sanitized; a dedicated test asserts the tool
  schema itself has no field named `status`/`decision`/`approve`/`reject`/`freeze`/`block`.
- **Authorization** (`api`, 5 tests): unauthenticated requests to `/api/alerts` are
  rejected; a `viewer` can read but gets `403` on the decision endpoint; a
  `Decision`-shaped bad value (`"ai_says_freeze_this_account"`) is rejected with `400`.
- **AI-cannot-decide** (the specific proof requested): `alerts::tests::ai_advisory_never_changes_alert_status`
  and `api::tests::ai_advisory_cannot_be_submitted_as_a_decision` — the latter operates
  at the HTTP layer, attempting to POST AI-style free text as a decision and confirming
  it's rejected.
- **Audit trail** (`audit`, 3 tests + `storage`, 4 tests): hash-chain validity,
  append-only decision history, and tamper detection (mutating a stored record's JSON
  breaks `verify_chain`).
- **Ingestion** (`ingestion`, 5 tests): Horizon JSON normalization (payments, credit
  assets, `create_account`), retry-then-succeed on a transient `503`, and per-transaction
  failure isolation (one bad transaction doesn't drop the rest of the batch).
- **Soroban contract** (4 tests, separate workspace): anchor/read-back, a later decision
  overwriting an earlier anchor for the same alert, an unanchored alert returning
  `None`, and double-`initialize` failing.

All of the above were also exercised live: the server was run end-to-end (demo mode),
logged in, listed and inspected alerts, submitted a decision through the dashboard form,
verified the audit chain over HTTP, and confirmed a direct SQL edit to a stored audit
record is detected by `verify_chain`.

## Failure handling

- **AI service unavailable** (no key, network error, timeout, malformed/refused
  response): the alert is still created and fully usable; `AiAdvisoryStatus::Unavailable`
  is recorded with a reason, and the human review workflow is entirely unaffected. See
  `ai_advisor::client::AnthropicAdvisor::investigate` and
  `alerts::AlertService::record_ai_unavailable`.
- **Ingestion source unreachable**: `HorizonTransactionSource` retries transient HTTP
  errors with exponential backoff before surfacing an error; the background poll loop
  (`api::pipeline::run_source`) logs and retries after the poll interval rather than
  exiting, so a Horizon outage pauses new ingestion without killing the service.
- **A single transaction fails to process** (normalize, evaluate, or persist): it's
  routed to `ingestion_dead_letter` with the error and isn't silently dropped; the rest
  of the batch still processes.
- **On-chain anchoring unavailable** (`stellar` CLI missing, network issue): logged and
  ignored — the decision itself already succeeded and was recorded off-chain before
  anchoring is even attempted.

## Security considerations

- **Passwords**: hashed with Argon2 (`argon2` crate), never stored or logged in plain
  text.
- **Sessions**: JWT signed with `JWT_SECRET`; always override the default in any shared
  or long-lived deployment. Tokens expire after 12 hours.
- **Authorization**: every alert-reading endpoint requires authentication; the decision
  endpoint additionally requires the `investigator` or `admin` role, checked
  server-side (`auth::require_decision_role`) — never inferred from what the UI happens
  to render.
- **AI output is treated as untrusted input** end-to-end: strict tool-call schema,
  server-side sanitization (`ai_advisor::validate`), and independent HTML-escaping at
  render time (`api::html::esc`). Nothing derived from model output is ever
  interpolated into a SQL query (all persistence goes through parameterized `sqlx`
  queries) or executed as a command.
- **Internal error detail isn't leaked**: `ApiError::Internal` logs the underlying
  detail server-side via `tracing` and returns a generic message to the client.
- **Correlation without over-collection**: structured logs carry `tx_id`, `alert_id`,
  and `investigation`-relevant identifiers for tracing an event through the pipeline,
  but never secrets (API keys, password hashes, JWTs) and never more account history
  than a given log line needs.
- **Known gaps for a real deployment** (reference implementation scope): no rate
  limiting on `/api/auth/login`; the seeded default admin password must be rotated
  immediately; SQLite is used for zero-setup portability — a production deployment
  handling real volume should move to Postgres (the repository-trait boundaries in
  `alerts`/`audit` make that a `storage`-crate-only change).
