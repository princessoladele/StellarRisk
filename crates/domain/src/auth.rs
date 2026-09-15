use serde::{Deserialize, Serialize};

/// Investigator roles. Only `Investigator` and `Admin` may submit a final decision on an
/// alert; `Viewer` is read-only (e.g. an auditor or compliance reviewer who should see
/// everything but never act).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Investigator,
    Admin,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Investigator => "investigator",
            Role::Admin => "admin",
        }
    }

    /// Whether this role is authorized to record a final decision on an alert.
    pub fn can_decide(&self) -> bool {
        matches!(self, Role::Investigator | Role::Admin)
    }

    /// Whether this role can manage flagged accounts / ingestion config.
    pub fn can_administer(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "viewer" => Ok(Role::Viewer),
            "investigator" => Ok(Role::Investigator),
            "admin" => Ok(Role::Admin),
            other => Err(format!("unknown role: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Investigator {
    pub id: String,
    pub username: String,
    pub role: Role,
}
