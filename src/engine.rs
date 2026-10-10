use crate::types::{Checker, Finding, ProgressMsg, ProgressReporter, Severity, Status};
use colored::*;
use std::io::{IsTerminal, Write};
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
        self.execute_with_progress(std::io::stderr().is_terminal())
            .await
    }

    pub async fn execute_with_progress(&self, show_spinner: bool) -> AuditReport {
        let start = std::time::Instant::now();
        let total = self.checkers.len();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ProgressMsg>();
        let reporter = ProgressReporter::new(tx.clone());

        let spinner_handle = if show_spinner && total > 0 {
            Some(tokio::spawn(async move {
                const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let mut frame_idx = 0;
                let start_time = std::time::Instant::now();
                let mut active_domains = std::collections::HashSet::new();
                let mut completed = 0;
                let mut current_op = String::from("Initializing security probes...");
                let mut interval = tokio::time::interval(std::time::Duration::from_millis(80));

                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let frame = SPINNER_FRAMES[frame_idx % SPINNER_FRAMES.len()];
                            frame_idx += 1;
                            let elapsed = start_time.elapsed().as_secs_f32();
                            let max_len = 50;
                            let display_op = if current_op.chars().count() > max_len {
                                let s: String = current_op.chars().take(max_len - 3).collect();
                                format!("{}...", s)
                            } else {
                                current_op.clone()
                            };

                            eprint!(
                                "\r\x1b[2K  {} [{}/{}] {} ({:.1}s)",
                                frame.cyan().bold(),
                                completed,
                                total,
                                display_op.dimmed(),
                                elapsed
                            );
                            let _ = std::io::stderr().flush();
                        }
                        msg = rx.recv() => {
                            match msg {
                                Some(ProgressMsg::Started { domain }) => {
                                    active_domains.insert(domain);
                                    current_op = format!("Auditing {}", domain);
                                }
                                Some(ProgressMsg::Step { detail }) => {
                                    current_op = detail;
                                }
                                Some(ProgressMsg::Completed { domain }) => {
                                    active_domains.remove(&domain);
                                    completed += 1;
                                    if completed >= total {
                                        break;
                                    }
                                    if let Some(next_domain) = active_domains.iter().next() {
                                        current_op = format!("Auditing {}", next_domain);
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }

                // Clear the loader line cleanly
                eprint!("\r\x1b[2K");
                let _ = std::io::stderr().flush();
            }))
        } else {
            None
        };

        let mut join_set = JoinSet::new();

        for checker in &self.checkers {
            let ch = Arc::clone(checker);
            let rep = reporter.clone();
            let domain = ch.domain();
            join_set.spawn(async move {
                rep.started(domain);
                let findings = ch.run_with_progress(&rep).await;
                rep.completed(domain);
                findings
            });
        }

        drop(reporter);
        drop(tx);

        let mut findings = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok(mut check_findings) = res {
                findings.append(&mut check_findings);
            }
        }
        let duration = start.elapsed();

        if let Some(handle) = spinner_handle {
            let _ = handle.await;
        }

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
