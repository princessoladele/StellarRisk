use domain::RuleTrigger;

use crate::context::EvaluationContext;
use crate::rule::Rule;
use crate::rules::built_in_rules;

/// Holds the active set of rules. New fraud checks are added by implementing [`Rule`]
/// and calling [`RuleRegistry::register`] — the engine itself never needs to change.
pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn with_built_ins() -> Self {
        Self { rules: built_in_rules() }
    }

    pub fn register(&mut self, rule: Box<dyn Rule>) -> &mut Self {
        self.rules.push(rule);
        self
    }

    pub fn rule_ids(&self) -> Vec<&'static str> {
        self.rules.iter().map(|r| r.id()).collect()
    }

    /// Runs every registered rule against the context, in registration order, and
    /// returns the concatenated list of triggers. Deterministic: the same context always
    /// produces the same triggers in the same order.
    pub fn evaluate_all(&self, ctx: &EvaluationContext) -> Vec<RuleTrigger> {
        self.rules.iter().flat_map(|rule| rule.evaluate(ctx)).collect()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::with_built_ins()
    }
}
