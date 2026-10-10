use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Skipped { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub domain: &'static str,
    pub check_id: String,
    pub title: String,
    pub severity: Severity,
    pub status: Status,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
    pub nixos_fix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_url: Option<&'static str>,
}

#[async_trait]
pub trait Checker: Send + Sync {
    fn domain(&self) -> &'static str;
    async fn run(&self) -> Vec<Finding>;
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
