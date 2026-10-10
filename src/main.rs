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

    /// Generate a ready-to-import NixOS hardening module (.nix) containing remediation settings for all failed checks (pass '-' for stdout)
    #[arg(short, long, value_name = "HARDENING.nix")]
    generate_fix: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!(
        "{}",
        "================================================================================"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "         nix-sentinel: NixOS Deep Threat & Security Audit Engine                "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "================================================================================"
            .cyan()
            .bold()
    );

    if !types::is_root() {
        println!("{}", " ⚠ [!] Running as unprivileged user. Privileged probes (shadow, bpf) gracefully skipped.\n".yellow().bold());
    }

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
        println!(
            "\n{} {}",
            "◆".blue().bold(),
            domain.bold().white().underline()
        );

        for f in findings {
            if args.failures_only && f.status == Status::Pass {
                continue;
            }

            let status_badge = match &f.status {
                Status::Pass => " PASS ".on_green().black().bold(),
                Status::Warn => " WARN ".on_yellow().black().bold(),
                Status::Fail => " FAIL ".on_red().white().bold(),
                Status::Skipped { .. } => " SKIP ".on_bright_black().white().bold(),
            };

            let severity_badge = match f.severity {
                Severity::Critical => "[CRIT]".red().bold(),
                Severity::High => "[HIGH]".bright_red(),
                Severity::Medium => "[MED] ".yellow(),
                Severity::Low => "[LOW] ".cyan(),
                Severity::Info => "[INFO]".dimmed(),
            };

            println!(
                "  {} {} {:<32} │ {}",
                status_badge,
                severity_badge,
                f.check_id.bold(),
                f.title
            );

            let has_items = !f.items.is_empty();
            let has_docs = f.doc_url.is_some();
            let has_fix =
                (f.status == Status::Fail || f.status == Status::Warn) && f.nixos_fix.is_some();

            let first_branch = if has_items || has_docs || has_fix {
                "├─"
            } else {
                "└─"
            };

            match &f.status {
                Status::Pass => {
                    println!("     {} Details : {}", first_branch, f.description.green());
                }
                Status::Warn => {
                    println!("     {} Warning : {}", first_branch, f.description.yellow());
                }
                Status::Skipped { reason } => {
                    println!("     {} Reason  : {}", first_branch, reason.dimmed());
                }
                Status::Fail => {
                    println!("     {} Details : {}", first_branch, f.description.dimmed());
                }
            }

            // Structured preview of detected entities
            if has_items {
                let items_branch = if has_docs || has_fix {
                    "├─"
                } else {
                    "└─"
                };
                println!(
                    "     {} Detected Entities ({}):",
                    items_branch,
                    f.items.len().to_string().bold()
                );
                let max_preview = 4;
                for (idx, item) in f.items.iter().take(max_preview).enumerate() {
                    let branch = if idx == f.items.len() - 1
                        || (idx == max_preview - 1 && f.items.len() > max_preview)
                    {
                        "└─"
                    } else {
                        "├─"
                    };
                    let indent = if has_docs || has_fix {
                        "│   "
                    } else {
                        "    "
                    };
                    println!("     {}{} {}", indent, branch.dimmed(), item.yellow());
                }
                if f.items.len() > max_preview {
                    let remaining = f.items.len() - max_preview;
                    let indent = if has_docs || has_fix {
                        "│   "
                    } else {
                        "    "
                    };
                    println!(
                        "     {}└─ ... and {} more (inspect full report via -o/--output)",
                        indent,
                        remaining.to_string().cyan().bold()
                    );
                }
            }

            // Clickable documentation URL (OSC 8 terminal hyperlink standard + styled URL)
            if let Some(url) = f.doc_url {
                let doc_branch = if has_fix { "├─" } else { "└─" };
                let clickable = format!(
                    "\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\",
                    url,
                    url.underline().bright_cyan()
                );
                println!("     {} Docs    : {}", doc_branch, clickable);
            }

            if has_fix {
                if let Some(fix) = &f.nixos_fix {
                    let formatted_fix = fix.trim().replace('\n', "\n        ");
                    println!(
                        "     └─ {} {}",
                        "NixOS Fix:".bright_magenta().bold(),
                        formatted_fix.cyan()
                    );
                }
            }
        }
    }

    println!(
        "\n{}",
        "================================================================================"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "                              AUDIT SUMMARY REPORT                              "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "================================================================================"
            .cyan()
            .bold()
    );
    println!(
        "  Total Checks Evaluated : {}",
        report.findings.len().to_string().white().bold()
    );
    println!(
        "  Passed                 : {}",
        report.passed.to_string().green().bold()
    );
    println!(
        "  Warnings               : {}",
        report.warned.to_string().yellow().bold()
    );
    println!(
        "  Failed                 : {}",
        report.failed.to_string().red().bold()
    );
    println!(
        "  Skipped                : {}",
        report.skipped.to_string().dimmed().bold()
    );

    let score_str = format!("{:.1}%", report.security_score);
    let colored_score = if report.security_score >= 85.0 {
        score_str.green().bold()
    } else if report.security_score >= 60.0 {
        score_str.yellow().bold()
    } else {
        score_str.red().bold()
    };
    println!("  Target Security Score  : {}", colored_score);
    println!(
        "{}\n",
        "================================================================================"
            .cyan()
            .bold()
    );

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
