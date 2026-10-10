use crate::types::{Checker, Finding, Severity, Status};
use colored::*;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

#[derive(Default)]
pub struct AuditEngine {
    checkers: Vec<Arc<dyn Checker>>,
}

pub struct AuditReport {
    pub findings: Vec<Finding>,
    pub security_score: f64,
    pub passed: usize,
    pub warned: usize,
    pub failed: usize,
    pub skipped: usize,
}

pub enum AuditProgressEvent {
    Started { domain: &'static str },
    Completed { domain: &'static str, count: usize },
}

#[macro_export]
macro_rules! register_checkers {
    ($engine:expr, $( $checker:expr ),* $(,)?) => {
        $(
            $engine.register($checker);
        )*
    };
}

impl AuditEngine {
    pub fn new() -> Self {
        Self {
            checkers: Vec::new(),
        }
    }

    pub fn register<C: Checker + 'static>(&mut self, checker: C) {
        self.checkers.push(Arc::new(checker));
    }

    pub async fn execute(&self) -> AuditReport {
        let (tx, mut rx) = mpsc::unbounded_channel::<AuditProgressEvent>();
        let mut join_set = JoinSet::new();

        println!(
            "{}",
            "── Active Audit Progress ───────────────────────────────────────────────────────"
                .dimmed()
        );

        for checker in &self.checkers {
            let ch = Arc::clone(checker);
            let tx_ch = tx.clone();
            join_set.spawn(async move {
                let domain = ch.domain();
                let _ = tx_ch.send(AuditProgressEvent::Started { domain });
                let findings = ch.run().await;
                let _ = tx_ch.send(AuditProgressEvent::Completed {
                    domain,
                    count: findings.len(),
                });
                findings
            });
        }
        drop(tx);

        let progress_task = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    AuditProgressEvent::Started { domain } => {
                        println!(
                            "  {} Scanning domain: {}",
                            "⚡".yellow().bold(),
                            domain.white().bold()
                        );
                    }
                    AuditProgressEvent::Completed { domain, count } => {
                        println!(
                            "  {} Finished domain: {} ({} probes evaluated)",
                            "✔".green().bold(),
                            domain.green(),
                            count.to_string().cyan().bold()
                        );
                    }
                }
            }
        });

        let mut findings = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok(mut check_findings) = res {
                findings.append(&mut check_findings);
            }
        }

        let _ = progress_task.await;
        println!(
            "{}\n",
            "────────────────────────────────────────────────────────────────────────────────"
                .dimmed()
        );

        let mut passed = 0;
        let mut warned = 0;
        let mut failed = 0;
        let mut skipped = 0;
        let mut earned_weight: f64 = 0.0;
        let mut total_weight: f64 = 0.0;

        for f in &findings {
            let weight = match f.severity {
                Severity::Critical => 10.0,
                Severity::High => 7.0,
                Severity::Medium => 4.0,
                Severity::Low => 2.0,
                Severity::Info => 1.0,
            };

            match &f.status {
                Status::Pass => {
                    passed += 1;
                    earned_weight += weight;
                    total_weight += weight;
                }
                Status::Warn => {
                    warned += 1;
                    earned_weight += weight * 0.5; // Half credit for warnings
                    total_weight += weight;
                }
                Status::Fail => {
                    failed += 1;
                    total_weight += weight;
                }
                Status::Skipped { .. } => {
                    skipped += 1;
                }
            }
        }

        let security_score = if total_weight > 0.0 {
            ((earned_weight / total_weight) * 100.0).clamp(0.0, 100.0)
        } else {
            100.0
        };

        AuditReport {
            findings,
            security_score,
            passed,
            warned,
            failed,
            skipped,
        }
    }
}
