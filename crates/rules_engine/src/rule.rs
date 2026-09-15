use domain::RuleTrigger;

use crate::context::EvaluationContext;

/// One deterministic fraud/anomaly check. Implementations must be pure functions of the
/// `EvaluationContext` they're given — no I/O, no wall-clock reads, no randomness — so
/// that running the same transaction through the same history twice always yields the
/// same triggers with the same reasons. This is what makes the engine explainable and
/// auditable: every trigger can be reproduced and defended after the fact.
pub trait Rule: Send + Sync {
    /// Stable machine identifier, used in audit records and configuration.
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    /// Returns zero or more triggers (a rule may fire once per offending movement, e.g.
    /// large-transfer on two different assets in the same transaction).
    fn evaluate(&self, ctx: &EvaluationContext) -> Vec<RuleTrigger>;
}
