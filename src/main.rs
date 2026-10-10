mod checks;
mod engine;
mod fix_generator;
mod types;

use clap::Parser;
use colored::*;
use engine::AuditEngine;
use fix_generator::NixFixGenerator;
use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::IsTerminal;
use types::{Severity, Status};

macro_rules! emit {
    ($dst:expr) => {{
        let _ = writeln!($dst);
    }};
    ($dst:expr, $($arg:tt)*) => {{
        let _ = writeln!($dst, $($arg)*);
    }};
}

#[derive(Parser, Debug)]
#[command(
    name = "fabel",
    author = "Principal Security Architecture Team",
    version = "0.3.0",
    about = "Host-based Threat Detection & Deep Security Audit Engine for NixOS",
    long_about = "fabel is a specialized Host Security & Integrity Audit Engine for NixOS.\nIt identifies configuration weaknesses, hidden interception channels, rootkits, and DPI interference,\nand can automatically generate ready-to-import declarative NixOS hardening configurations."
)]
struct Args {
    /// Save full audit report as structured JSON (e.g. -o report.json)
    #[arg(short, long, value_name = "REPORT.json")]
    output: Option<String>,

    /// Show only failed/warned checks (suppresses passing PASS checks)
    #[arg(short, long)]
    failures_only: bool,

    /// Show all evaluated checks and all details (table, pass/skip/warn/fail, docs links, items, and fixes)
    #[arg(short, long)]
    all: bool,

    /// Display only the high-level domain scorecard table without detailed issue cards
    #[arg(short, long)]
    table_only: bool,

    /// Show detailed verbose descriptions for all checks
    #[arg(short, long)]
    verbose: bool,

    /// Disable interactive pager (less) and print output directly to stdout
    #[arg(long)]
    no_pager: bool,

    /// Generate a ready-to-import NixOS hardening module (.nix) containing remediation settings for all failed checks (pass '-' for stdout)
    #[arg(short, long, value_name = "HARDENING.nix")]
    generate_fix: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if std::io::stdout().is_terminal() {
        colored::control::set_override(true);
    }

    let mut out = String::new();

    emit!(out);
    emit!(
        out,
        "  {}  {} {}",
        "🛡️".bold(),
        "fabel".cyan().bold(),
        "v0.3.0".dimmed()
    );
    emit!(
        out,
        "  {}",
        "Host Threat Detection & Hardening Audit for NixOS".dimmed()
    );
    if !types::is_root() {
        emit!(
            out,
            "  {}",
            "⚡ Running unprivileged: root-only probes (shadow, bpf) safely skipped.".yellow()
        );
    }
    emit!(out);

    let mut engine = AuditEngine::new();

    // Macro-based clean registration (DRY)
    register_checkers!(
        engine,
        checks::pki::PkiChecker,
        checks::network_dpi::NetworkDpiChecker,
        checks::internet_intercept::InternetInterceptChecker,
        checks::live_network::LiveNetworkChecker,
        checks::network_firewall::NetworkFirewallChecker,
        checks::data_leaks::DataLeaksChecker,
        checks::anti_forensics::AntiForensicsChecker,
        checks::stealth::StealthChecker,
        checks::boot_hardening::BootHardeningChecker,
        checks::hardware_cpu::HardwareCpuChecker,
        checks::peripheral::PeripheralChecker,
        checks::core_dumps::CoreDumpsChecker,
        checks::ssh::SshChecker,
        checks::nixos::NixosChecker,
        checks::integrity::IntegrityChecker,
        checks::access::AccessChecker,
    );

    let report = engine.execute().await;

    // Group findings by domain
    let mut domains: BTreeMap<&'static str, Vec<&types::Finding>> = BTreeMap::new();
    for f in &report.findings {
        domains.entry(f.domain).or_default().push(f);
    }

    // 1. Detailed Actionable Findings (unless --table-only is passed)
    if !args.table_only {
        let domains_with_findings: Vec<_> = domains
            .iter()
            .filter(|(_, findings)| {
                args.all
                    || findings
                        .iter()
                        .any(|f| f.status == Status::Fail || f.status == Status::Warn)
            })
            .collect();

        let total_issues: usize = domains
            .values()
            .map(|findings| {
                findings
                    .iter()
                    .filter(|f| f.status == Status::Fail || f.status == Status::Warn)
                    .count()
            })
            .sum();

        if total_issues == 0 && !args.all {
            emit!(out);
            emit!(
                out,
                "  {} {}",
                "✔".green().bold(),
                "All security checks passed! No vulnerabilities or hardening issues detected."
                    .green()
                    .bold()
            );
        } else {
            emit!(out);
            let header_title = if args.all {
                format!(
                    "━━━ Complete Security Audit Details ({} checks, {} issues detected) ━━━━━━━━━━",
                    report.findings.len(),
                    total_issues
                )
            } else {
                format!(
                    "━━━ Actionable Security Findings ({} issues detected) ━━━━━━━━━━━━━━━━━━━━",
                    total_issues
                )
            };
            emit!(out, "  {}", header_title.yellow().bold());

            let show_all_info = args.all || args.verbose;

            for (domain, findings) in domains_with_findings {
                let relevant: Vec<_> = findings
                    .iter()
                    .filter(|f| args.all || f.status == Status::Fail || f.status == Status::Warn)
                    .collect();

                if relevant.is_empty() {
                    continue;
                }

                emit!(out, "\n  {} {}", "▶".cyan().bold(), domain.bold().white());

                for f in relevant {
                    match &f.status {
                        Status::Pass => {
                            if args.all {
                                emit!(out);
                                emit!(
                                    out,
                                    "    {}  {:<32} {}",
                                    "✔ PASS".green().bold(),
                                    f.check_id.white(),
                                    f.title.dimmed()
                                );
                                emit!(
                                    out,
                                    "       {:<7} {}",
                                    "Details:".dimmed(),
                                    f.description.green()
                                );
                                if !f.items.is_empty() {
                                    emit!(
                                        out,
                                        "       {:<7} {}",
                                        "Items:".dimmed(),
                                        f.items.join(", ").cyan()
                                    );
                                }
                                if let Some(url) = f.doc_url {
                                    emit!(
                                        out,
                                        "       {:<7} {}",
                                        "Docs:".dimmed(),
                                        url.underline().dimmed()
                                    );
                                }
                            }
                        }
                        Status::Skipped { reason } => {
                            if show_all_info {
                                emit!(out);
                                emit!(
                                    out,
                                    "    {}  {:<32} {}",
                                    "– SKIP".dimmed(),
                                    f.check_id.dimmed(),
                                    f.title.dimmed()
                                );
                                emit!(out, "       {:<7} {}", "Reason:".dimmed(), reason.dimmed());
                                if let Some(url) = f.doc_url {
                                    emit!(
                                        out,
                                        "       {:<7} {}",
                                        "Docs:".dimmed(),
                                        url.underline().dimmed()
                                    );
                                }
                            }
                        }
                        Status::Warn => {
                            let sev = match f.severity {
                                Severity::Critical => "[CRIT]".red().bold(),
                                Severity::High => "[HIGH]".bright_red().bold(),
                                Severity::Medium => "[MED] ".yellow().bold(),
                                Severity::Low => "[LOW] ".cyan(),
                                Severity::Info => "[INFO]".dimmed(),
                            };
                            emit!(out);
                            if show_all_info {
                                emit!(
                                    out,
                                    "    {} {} {:<32} {}",
                                    "⚠ WARN".on_yellow().black().bold(),
                                    sev,
                                    f.check_id.bold().yellow(),
                                    f.title.dimmed()
                                );
                            } else {
                                emit!(
                                    out,
                                    "    {} {} {}",
                                    "⚠ WARN".on_yellow().black().bold(),
                                    sev,
                                    f.check_id.bold().yellow()
                                );
                            }
                            emit!(out, "       {:<7} {}", "Issue:".yellow(), f.description);
                            if let Some(fix) = &f.nixos_fix {
                                let formatted_fix = fix.trim().replace('\n', "\n               ");
                                emit!(
                                    out,
                                    "       {:<7} {}",
                                    "Fix:".bright_magenta().bold(),
                                    formatted_fix.cyan()
                                );
                            }
                            if show_all_info {
                                if !f.items.is_empty() {
                                    emit!(
                                        out,
                                        "       {:<7} {}",
                                        "Items:".dimmed(),
                                        f.items.join(", ").cyan()
                                    );
                                }
                                if let Some(url) = f.doc_url {
                                    emit!(
                                        out,
                                        "       {:<7} {}",
                                        "Docs:".dimmed(),
                                        url.underline().dimmed()
                                    );
                                }
                            }
                        }
                        Status::Fail => {
                            let sev = match f.severity {
                                Severity::Critical => "[CRIT]".on_red().white().bold(),
                                Severity::High => "[HIGH]".bright_red().bold(),
                                Severity::Medium => "[MED] ".yellow().bold(),
                                Severity::Low => "[LOW] ".cyan(),
                                Severity::Info => "[INFO]".dimmed(),
                            };
                            emit!(out);
                            if show_all_info {
                                emit!(
                                    out,
                                    "    {} {} {:<32} {}",
                                    "✖ FAIL".on_red().white().bold(),
                                    sev,
                                    f.check_id.bold().red(),
                                    f.title.dimmed()
                                );
                            } else {
                                emit!(
                                    out,
                                    "    {} {} {}",
                                    "✖ FAIL".on_red().white().bold(),
                                    sev,
                                    f.check_id.bold().red()
                                );
                            }
                            emit!(out, "       {:<7} {}", "Issue:".red(), f.description);
                            if let Some(fix) = &f.nixos_fix {
                                let formatted_fix = fix.trim().replace('\n', "\n               ");
                                emit!(
                                    out,
                                    "       {:<7} {}",
                                    "Fix:".bright_magenta().bold(),
                                    formatted_fix.cyan()
                                );
                            }
                            if show_all_info {
                                if !f.items.is_empty() {
                                    emit!(
                                        out,
                                        "       {:<7} {}",
                                        "Items:".dimmed(),
                                        f.items.join(", ").yellow()
                                    );
                                }
                                if let Some(url) = f.doc_url {
                                    emit!(
                                        out,
                                        "       {:<7} {}",
                                        "Docs:".dimmed(),
                                        url.underline().dimmed()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. High-level Domain Scorecard Table (at the bottom)
    emit!(out);
    emit!(
        out,
        "  ┌{}┬{}┬{}┬{}┐",
        "─".repeat(54),
        "─".repeat(12),
        "─".repeat(16),
        "─".repeat(10)
    );
    emit!(
        out,
        "  │ {:<52} │ {:<10} │ {:<14} │ {:>8} │",
        "Security Domain".bold().white(),
        "Probes".bold().white(),
        "Status".bold().white(),
        "Score ".bold().white()
    );
    emit!(
        out,
        "  ├{}┼{}┼{}┼{}┤",
        "─".repeat(54),
        "─".repeat(12),
        "─".repeat(16),
        "─".repeat(10)
    );

    for (domain, findings) in &domains {
        let _pass_count = findings.iter().filter(|f| f.status == Status::Pass).count();
        let warn_count = findings.iter().filter(|f| f.status == Status::Warn).count();
        let fail_count = findings.iter().filter(|f| f.status == Status::Fail).count();

        // Calculate domain score
        let mut earned: f64 = 0.0;
        let mut total: f64 = 0.0;
        for f in findings {
            let weight = match f.severity {
                Severity::Critical => 10.0,
                Severity::High => 7.0,
                Severity::Medium => 4.0,
                Severity::Low => 2.0,
                Severity::Info => 1.0,
            };
            match &f.status {
                Status::Pass => {
                    earned += weight;
                    total += weight;
                }
                Status::Warn => {
                    earned += weight * 0.5;
                    total += weight;
                }
                Status::Fail => {
                    total += weight;
                }
                Status::Skipped { .. } => {}
            }
        }
        let domain_score = if total > 0.0 {
            ((earned / total) * 100.0).clamp(0.0, 100.0)
        } else {
            100.0
        };

        let domain_name = if domain.len() > 52 {
            format!("{}...", &domain[..49])
        } else {
            domain.to_string()
        };

        let probes_str = format!("{} chks", findings.len());

        let status_colored = if fail_count > 0 {
            format!("{:<14}", format!("✖ FAIL ({})", fail_count))
                .red()
                .bold()
        } else if warn_count > 0 {
            format!("{:<14}", format!("⚠ WARN ({})", warn_count))
                .yellow()
                .bold()
        } else {
            format!("{:<14}", "✔ PASS").green().bold()
        };

        let score_raw = format!("{:.0}%", domain_score);
        let score_padded = format!("{:>7} ", score_raw);
        let score_colored = if domain_score >= 85.0 {
            score_padded.green().bold()
        } else if domain_score >= 60.0 {
            score_padded.yellow().bold()
        } else {
            score_padded.red().bold()
        };

        emit!(
            out,
            "  │ {:<52} │ {:<10} │ {} │ {} │",
            domain_name,
            probes_str.dimmed(),
            status_colored,
            score_colored
        );
    }

    emit!(
        out,
        "  └{}┴{}┴{}┴{}┘",
        "─".repeat(54),
        "─".repeat(12),
        "─".repeat(16),
        "─".repeat(10)
    );

    // Severity vulnerability counts for dashboard
    let mut crit_count = 0;
    let mut high_count = 0;
    let mut med_count = 0;
    let mut low_count = 0;
    for f in &report.findings {
        if f.status == Status::Fail || f.status == Status::Warn {
            match f.severity {
                Severity::Critical => crit_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => med_count += 1,
                Severity::Low | Severity::Info => low_count += 1,
            }
        }
    }

    let score_status = if report.security_score >= 85.0 {
        format!("{:.1}%  [ HARDENED ]", report.security_score)
            .green()
            .bold()
    } else if report.security_score >= 60.0 {
        format!("{:.1}%  [ MODERATE RISK ]", report.security_score)
            .yellow()
            .bold()
    } else {
        format!("{:.1}%  [ HIGH RISK ]", report.security_score)
            .red()
            .bold()
    };

    let dur_ms = report.duration.as_millis();
    let duration_str = format!("{}ms", dur_ms).dimmed();

    emit!(out);
    emit!(
        out,
        "  {}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━ AUDIT DASHBOARD ━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .cyan()
            .bold()
    );
    emit!(out);
    emit!(
        out,
        "   Security Score : {}  (Duration: {})",
        score_status,
        duration_str
    );
    emit!(
        out,
        "   Probes         : {} total  ·  {} pass  ·  {} warn  ·  {} fail{}",
        report.findings.len().to_string().bold(),
        report.passed.to_string().green().bold(),
        report.warned.to_string().yellow().bold(),
        report.failed.to_string().red().bold(),
        if report.skipped > 0 {
            format!("  ·  {} skip", report.skipped.to_string().dimmed())
        } else {
            String::new()
        }
    );
    emit!(out);
    emit!(out, "   Vulnerability Severity Breakdown:");
    emit!(
        out,
        "     Critical: {:<4}  High: {:<4}  Medium: {:<4}  Low: {}",
        crit_count.to_string().red().bold(),
        high_count.to_string().bright_red().bold(),
        med_count.to_string().yellow().bold(),
        low_count.to_string().cyan().bold()
    );
    emit!(out);
    emit!(out, "   Recommended Actions:");
    emit!(
        out,
        "   • Generate NixOS auto-fix : {}",
        "fabel -g /etc/nixos/hardening.nix".cyan()
    );
    emit!(
        out,
        "   • Export full JSON report : {}",
        "fabel -o report.json".cyan()
    );
    if !args.all {
        emit!(
            out,
            "   • View all passing checks : {}",
            "fabel --all".cyan()
        );
    }
    emit!(out);
    emit!(
        out,
        "  {}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .cyan()
            .bold()
    );
    emit!(out);

    // Export JSON report
    if let Some(path) = &args.output {
        match serde_json::to_string_pretty(&report.findings) {
            Ok(json) => {
                if let Err(e) = fs::write(path, json) {
                    emit!(out, "{}: {}", "Error writing JSON report".red(), e);
                } else {
                    emit!(
                        out,
                        "{} Structured JSON audit report ({} findings) saved to {}",
                        "✔".green(),
                        report.findings.len().to_string().bold(),
                        path.bold().cyan()
                    );
                }
            }
            Err(e) => emit!(out, "{}: {}", "Failed to serialize report".red(), e),
        }
    }

    // Generate declarative NixOS hardening configuration file
    if let Some(path) = &args.generate_fix {
        let (nix_module, sysctl_count, block_count) =
            NixFixGenerator::generate_nixos_module_with_stats(&report.findings);
        let total_fixes = sysctl_count + block_count;

        if path == "-" {
            println!(
                "\n{}",
                "--- [Generated Declarative NixOS Hardening Module] ---"
                    .bold()
                    .cyan()
            );
            println!("{}", nix_module);
            return;
        } else {
            match fs::write(path, &nix_module) {
                Ok(_) => {
                    emit!(out, "\n{}", "────────────────────────────────────────────────────────────────────────────────".dimmed());
                    emit!(
                        out,
                        "{} Declarative NixOS hardening module written to {}",
                        "✔".green().bold(),
                        path.bold().cyan()
                    );
                    emit!(out, "   ├─ Generated Fixes     : {} total ({} sysctl knobs, {} system/daemon declarations)",
                        total_fixes.to_string().bold().green(),
                        sysctl_count.to_string().cyan(),
                        block_count.to_string().cyan()
                    );
                    emit!(out, "   ├─ Module Architecture : Ready-to-import NixOS module (imports = [ ./{path} ])");
                    emit!(out, "   ├─ Contents            : Covers failed sysctl, disabled unneeded services, root protection, etc.");
                    emit!(out, "   └─ How to apply in NixOS:");
                    emit!(
                        out,
                        "        1. Review the generated settings: cat {}",
                        path.cyan()
                    );
                    emit!(
                        out,
                        "        2. Add to /etc/nixos/configuration.nix: imports = [ ./{path} ];"
                    );
                    emit!(
                        out,
                        "        3. Test & apply system configuration: sudo nixos-rebuild switch\n"
                    );
                }
                Err(e) => {
                    emit!(
                        out,
                        "{}: {}",
                        "Error writing declarative NixOS hardening file".red(),
                        e
                    );
                }
            }
        }
    }

    // Display output (interactive pager if running in terminal, or direct stdout)
    if !args.no_pager
        && std::io::stdout().is_terminal()
        && args.generate_fix.as_deref() != Some("-")
    {
        display_with_pager(&out);
    } else {
        print!("{}", out);
    }
}

fn display_with_pager(content: &str) {
    let pager = std::env::var("PAGER").unwrap_or_else(|_| "less".to_string());
    let mut parts = pager.split_whitespace();
    let cmd = parts.next().unwrap_or("less").to_string();
    let mut args: Vec<String> = parts.map(|s| s.to_string()).collect();

    // Default to less with -R for ANSI colors and alternate screen buffer
    if (cmd == "less" || cmd.ends_with("/less"))
        && !args.iter().any(|a| a.contains('R') || a.contains('r'))
    {
        args.push("-R".to_string());
    }

    match std::process::Command::new(&cmd)
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write as IoWrite;
                let _ = stdin.write_all(content.as_bytes());
            }
            let _ = child.wait();
        }
        Err(_) => {
            print!("{}", content);
        }
    }
}
