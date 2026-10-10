mod checks;
mod engine;
mod fix_generator;
mod types;

use clap::Parser;
use colored::*;
use engine::AuditEngine;
use fix_generator::NixFixGenerator;
use std::collections::BTreeMap;
use std::fs;
use types::{Severity, Status};

#[derive(Parser, Debug)]
#[command(
    name = "nix-sentinel",
    author = "Principal Security Architecture Team",
    version = "0.3.0",
    about = "Host-based Threat Detection & Deep Security Audit Engine for NixOS",
    long_about = "nix-sentinel is a specialized Host Security & Integrity Audit Engine for NixOS.\nIt identifies configuration weaknesses, hidden interception channels, rootkits, and DPI interference,\nand can automatically generate ready-to-import declarative NixOS hardening configurations."
)]
struct Args {
    /// Save full audit report as structured JSON (e.g. -o report.json)
    #[arg(short, long, value_name = "REPORT.json")]
    output: Option<String>,

    /// Show only failed/warned checks (suppresses passing PASS checks)
    #[arg(short, long)]
    failures_only: bool,

    /// Show detailed verbose descriptions for all passing checks
    #[arg(short, long)]
    verbose: bool,

    /// Generate a ready-to-import NixOS hardening module (.nix) containing remediation settings for all failed checks (pass '-' for stdout)
    #[arg(short, long, value_name = "HARDENING.nix")]
    generate_fix: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!();
    println!(
        "  {}  {} {}",
        "🛡️".bold(),
        "nix-sentinel".cyan().bold(),
        "v0.3.0".dimmed()
    );
    println!(
        "  {}",
        "Host Threat Detection & Hardening Audit for NixOS".dimmed()
    );
    if !types::is_root() {
        println!(
            "  {}",
            "⚡ Running unprivileged: root-only probes (shadow, bpf) safely skipped.".yellow()
        );
    }
    println!();

    let mut engine = AuditEngine::new();

    // Macro-based clean registration (DRY)
    register_checkers!(
        engine,
        checks::pki::PkiChecker,
        checks::network_dpi::NetworkDpiChecker,
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

    for (domain, findings) in &domains {
        let pass_count = findings.iter().filter(|f| f.status == Status::Pass).count();
        let warn_count = findings.iter().filter(|f| f.status == Status::Warn).count();
        let fail_count = findings.iter().filter(|f| f.status == Status::Fail).count();

        if args.failures_only && fail_count == 0 && warn_count == 0 {
            continue;
        }

        let status_badge = if fail_count == 0 && warn_count == 0 {
            format!("[ {}/{} passed ]", pass_count, findings.len())
                .green()
                .bold()
        } else {
            let mut parts = Vec::new();
            if pass_count > 0 {
                parts.push(format!("{} pass", pass_count).green().to_string());
            }
            if warn_count > 0 {
                parts.push(format!("{} warn", warn_count).yellow().bold().to_string());
            }
            if fail_count > 0 {
                parts.push(format!("{} fail", fail_count).red().bold().to_string());
            }
            format!("[ {} ]", parts.join(" · ")).normal()
        };

        let domain_header = format!("─── {} ", domain.bold().white());
        let total_chars = domain.len() + 4;
        let dashes_count = 72usize.saturating_sub(total_chars + 18);
        let dashes = "─".repeat(dashes_count);

        println!("\n{} {} {}", domain_header, dashes.dimmed(), status_badge);

        for f in findings {
            if args.failures_only && f.status == Status::Pass {
                continue;
            }

            match &f.status {
                Status::Pass => {
                    println!(
                        "   {}  {:<32} {}",
                        "✔".green().bold(),
                        f.check_id.white(),
                        f.title.dimmed()
                    );
                    if args.verbose {
                        println!("       {} {}", "Details:".dimmed(), f.description.green());
                    }
                }
                Status::Skipped { reason } => {
                    println!(
                        "   {}  {:<32} {} {}",
                        "–".dimmed(),
                        f.check_id.dimmed(),
                        f.title.dimmed(),
                        format!("({})", reason).dimmed()
                    );
                }
                Status::Warn => {
                    let severity_badge = match f.severity {
                        Severity::Critical => "[CRIT]".red().bold(),
                        Severity::High => "[HIGH]".bright_red().bold(),
                        Severity::Medium => "[MED] ".yellow().bold(),
                        Severity::Low => "[LOW] ".cyan(),
                        Severity::Info => "[INFO]".dimmed(),
                    };

                    println!();
                    println!(
                        "   {}  {}  {:<30} {}  {}",
                        "⚠".yellow().bold(),
                        "WARN".on_yellow().black().bold(),
                        f.check_id.bold().yellow(),
                        severity_badge,
                        f.title.bold().white()
                    );
                    println!("      {:<7} {}", "Issue:".yellow().bold(), f.description);

                    if !f.items.is_empty() {
                        let preview: Vec<String> =
                            f.items.iter().take(3).map(|s| s.to_string()).collect();
                        let mut items_str = preview.join(", ");
                        if f.items.len() > 3 {
                            items_str.push_str(&format!(" (+{} more)", f.items.len() - 3));
                        }
                        println!("      {:<7} {}", "Items:".dimmed(), items_str.cyan());
                    }

                    if let Some(fix) = &f.nixos_fix {
                        let formatted_fix = fix.trim().replace('\n', "\n              ");
                        println!(
                            "      {:<7} {}",
                            "Fix:".bright_magenta().bold(),
                            formatted_fix.cyan()
                        );
                    }

                    if let Some(url) = f.doc_url {
                        println!("      {:<7} {}", "Docs:".dimmed(), url.underline().dimmed());
                    }
                    println!();
                }
                Status::Fail => {
                    let severity_badge = match f.severity {
                        Severity::Critical => "[CRIT]".on_red().white().bold(),
                        Severity::High => "[HIGH]".bright_red().bold(),
                        Severity::Medium => "[MED] ".yellow().bold(),
                        Severity::Low => "[LOW] ".cyan(),
                        Severity::Info => "[INFO]".dimmed(),
                    };

                    println!();
                    println!(
                        "   {}  {}  {:<30} {}  {}",
                        "✖".red().bold(),
                        "FAIL".on_red().white().bold(),
                        f.check_id.bold().red(),
                        severity_badge,
                        f.title.bold().white()
                    );
                    println!("      {:<7} {}", "Issue:".red().bold(), f.description);

                    if !f.items.is_empty() {
                        let preview: Vec<String> =
                            f.items.iter().take(3).map(|s| s.to_string()).collect();
                        let mut items_str = preview.join(", ");
                        if f.items.len() > 3 {
                            items_str.push_str(&format!(" (+{} more)", f.items.len() - 3));
                        }
                        println!("      {:<7} {}", "Items:".dimmed(), items_str.yellow());
                    }

                    if let Some(fix) = &f.nixos_fix {
                        let formatted_fix = fix.trim().replace('\n', "\n              ");
                        println!(
                            "      {:<7} {}",
                            "Fix:".bright_magenta().bold(),
                            formatted_fix.cyan()
                        );
                    }

                    if let Some(url) = f.doc_url {
                        println!("      {:<7} {}", "Docs:".dimmed(), url.underline().dimmed());
                    }
                    println!();
                }
            }
        }
    }

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

    println!();
    println!(
        "  {}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━ AUDIT DASHBOARD ━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .cyan()
            .bold()
    );
    println!();
    println!(
        "   Security Score : {}  (Duration: {})",
        score_status, duration_str
    );
    println!(
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
    println!();
    println!("   Vulnerability Severity Breakdown:");
    println!(
        "     Critical: {:<4}  High: {:<4}  Medium: {:<4}  Low: {}",
        crit_count.to_string().red().bold(),
        high_count.to_string().bright_red().bold(),
        med_count.to_string().yellow().bold(),
        low_count.to_string().cyan().bold()
    );
    println!();
    println!("   Recommended Actions:");
    println!(
        "   • Generate NixOS auto-fix:  {}",
        "nix-sentinel -g /etc/nixos/hardening.nix".cyan()
    );
    println!(
        "   • Show failures only:       {}",
        "nix-sentinel -f".cyan()
    );
    println!(
        "   • Export full JSON report:  {}",
        "nix-sentinel -o report.json".cyan()
    );
    println!();
    println!(
        "  {}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .cyan()
            .bold()
    );
    println!();

    // Export JSON report
    if let Some(path) = args.output {
        match serde_json::to_string_pretty(&report.findings) {
            Ok(json) => {
                if let Err(e) = fs::write(&path, json) {
                    eprintln!("{}: {}", "Error writing JSON report".red(), e);
                } else {
                    println!(
                        "{} Structured JSON audit report ({} findings) saved to {}",
                        "✔".green(),
                        report.findings.len().to_string().bold(),
                        path.bold().cyan()
                    );
                }
            }
            Err(e) => eprintln!("{}: {}", "Failed to serialize report".red(), e),
        }
    }

    // Generate declarative NixOS hardening configuration file
    if let Some(path) = args.generate_fix {
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
        } else {
            match fs::write(&path, &nix_module) {
                Ok(_) => {
                    println!("\n{}", "────────────────────────────────────────────────────────────────────────────────".dimmed());
                    println!(
                        "{} Declarative NixOS hardening module written to {}",
                        "✔".green().bold(),
                        path.bold().cyan()
                    );
                    println!("   ├─ Generated Fixes     : {} total ({} sysctl knobs, {} system/daemon declarations)",
                        total_fixes.to_string().bold().green(),
                        sysctl_count.to_string().cyan(),
                        block_count.to_string().cyan()
                    );
                    println!("   ├─ Module Architecture : Ready-to-import NixOS module (imports = [ ./{path} ])");
                    println!("   ├─ Contents            : Covers failed sysctl, disabled unneeded services, root protection, etc.");
                    println!("   └─ How to apply in NixOS:");
                    println!(
                        "        1. Review the generated settings: cat {}",
                        path.cyan()
                    );
                    println!(
                        "        2. Add to /etc/nixos/configuration.nix: imports = [ ./{path} ];"
                    );
                    println!(
                        "        3. Test & apply system configuration: sudo nixos-rebuild switch\n"
                    );
                }
                Err(e) => {
                    eprintln!(
                        "{}: {}",
                        "Error writing declarative NixOS hardening file".red(),
                        e
                    );
                }
            }
        }
    }
}
