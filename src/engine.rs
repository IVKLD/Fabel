use crate::types::{Checker, Finding, Severity, Status};
use std::sync::Arc;
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
    pub duration: std::time::Duration,
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
        let start = std::time::Instant::now();
        let mut join_set = JoinSet::new();

        for checker in &self.checkers {
            let ch = Arc::clone(checker);
            join_set.spawn(async move { ch.run().await });
        }

        let mut findings = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok(mut check_findings) = res {
                findings.append(&mut check_findings);
            }
        }
        let duration = start.elapsed();

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
            duration,
        }
    }
}
