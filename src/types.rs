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

#[derive(Clone, Debug)]
pub enum ProgressMsg {
    Started { domain: &'static str },
    Step { detail: String },
    Completed { domain: &'static str },
}

#[derive(Clone, Debug)]
pub struct ProgressReporter {
    sender: tokio::sync::mpsc::UnboundedSender<ProgressMsg>,
}

impl ProgressReporter {
    pub fn new(sender: tokio::sync::mpsc::UnboundedSender<ProgressMsg>) -> Self {
        Self { sender }
    }

    pub fn started(&self, domain: &'static str) {
        let _ = self.sender.send(ProgressMsg::Started { domain });
    }

    pub fn step(&self, _domain: &'static str, detail: impl Into<String>) {
        let _ = self.sender.send(ProgressMsg::Step {
            detail: detail.into(),
        });
    }

    pub fn completed(&self, domain: &'static str) {
        let _ = self.sender.send(ProgressMsg::Completed { domain });
    }

    pub fn noop() -> Self {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        Self { sender: tx }
    }
}

#[async_trait]
pub trait Checker: Send + Sync {
    fn domain(&self) -> &'static str;
    async fn run(&self) -> Vec<Finding>;
    async fn run_with_progress(&self, _progress: &ProgressReporter) -> Vec<Finding> {
        self.run().await
    }
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
