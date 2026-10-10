use crate::types::{Finding, Status};
use std::collections::BTreeSet;

pub struct NixFixGenerator;

impl NixFixGenerator {
    #[allow(dead_code)]
    pub fn generate_nixos_module(findings: &[Finding]) -> String {
        Self::generate_nixos_module_with_stats(findings).0
    }

    fn extract_quotes(text: &str) -> Vec<String> {
        let mut results = Vec::new();
        let mut in_quote = false;
        let mut current = String::new();

        for ch in text.chars() {
            if ch == '"' {
                if in_quote {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        results.push(trimmed.to_string());
                    }
                    current.clear();
                    in_quote = false;
                } else {
                    in_quote = true;
                }
            } else if in_quote {
                current.push(ch);
            }
        }
        results
    }

    pub fn generate_nixos_module_with_stats(findings: &[Finding]) -> (String, usize, usize) {
        let mut sysctl_lines = BTreeSet::new();
        let mut kernel_params = BTreeSet::new();
        let mut blacklisted_modules = BTreeSet::new();
        let mut raw_blocks = Vec::new();

        for f in findings {
            if f.status == Status::Fail || f.status == Status::Warn {
                if let Some(fix) = &f.nixos_fix {
                    let trimmed_fix = fix.trim();

                    // 1. Sysctl
                    if trimmed_fix.starts_with("boot.kernel.sysctl.") {
                        for line in trimmed_fix.lines() {
                            let l = line.trim();
                            if l.starts_with("boot.kernel.sysctl.") {
                                let sub = l.trim_start_matches("boot.kernel.sysctl.");
                                if let Some((k, v)) = sub.split_once('=') {
                                    let key = k.trim().trim_matches('"');
                                    let val = v.trim().trim_end_matches(';');
                                    sysctl_lines.insert(format!("    \"{}\" = {};", key, val));
                                }
                            }
                        }
                        continue;
                    }

                    // 2. Separate lines into kernelParams, blacklistedKernelModules, or raw
                    let mut remaining_lines = Vec::new();
                    let mut in_kernel_params_block = false;
                    let mut in_blacklist_block = false;

                    for line in trimmed_fix.lines() {
                        let l = line.trim();

                        if l.starts_with("boot.kernelParams") {
                            for q in Self::extract_quotes(line) {
                                kernel_params.insert(q);
                            }
                            if !l.contains(';') && l.contains('[') && !l.contains(']') {
                                in_kernel_params_block = true;
                            }
                            continue;
                        }

                        if in_kernel_params_block {
                            for q in Self::extract_quotes(line) {
                                kernel_params.insert(q);
                            }
                            if l.contains(']') {
                                in_kernel_params_block = false;
                            }
                            continue;
                        }

                        if l.starts_with("boot.blacklistedKernelModules") {
                            for q in Self::extract_quotes(line) {
                                blacklisted_modules.insert(q);
                            }
                            if !l.contains(';') && l.contains('[') && !l.contains(']') {
                                in_blacklist_block = true;
                            }
                            continue;
                        }

                        if in_blacklist_block {
                            for q in Self::extract_quotes(line) {
                                blacklisted_modules.insert(q);
                            }
                            if l.contains(']') {
                                in_blacklist_block = false;
                            }
                            continue;
                        }

                        remaining_lines.push(line);
                    }

                    let clean_remaining = remaining_lines.join("\n").trim().to_string();
                    if !clean_remaining.is_empty() {
                        let mut block_with_comment = String::new();
                        block_with_comment.push_str(&format!("  # [{}] {}\n", f.check_id, f.title));
                        if let Some(url) = f.doc_url {
                            block_with_comment.push_str(&format!("  # Docs: {}\n", url));
                        }
                        let indented_block = clean_remaining
                            .lines()
                            .map(|l| format!("  {}", l))
                            .collect::<Vec<_>>()
                            .join("\n");
                        block_with_comment.push_str(&indented_block);
                        raw_blocks.push(block_with_comment);
                    }
                }
            }
        }

        let sysctl_count = sysctl_lines.len();
        let total_declarations = raw_blocks.len()
            + (if kernel_params.is_empty() { 0 } else { 1 })
            + (if blacklisted_modules.is_empty() { 0 } else { 1 });

        let mut output = String::new();
        output
            .push_str("# =====================================================================\n");
        output.push_str("# Autogenerated NixOS Hardening Profile by fabel\n");
        output.push_str("# Include this file in /etc/nixos/configuration.nix via:\n");
        output.push_str("#   imports = [ ./sentinel-hardening.nix ];\n");
        output.push_str(
            "# =====================================================================\n\n",
        );
        output.push_str("{ config, pkgs, lib, ... }:\n\n{\n");

        if !sysctl_lines.is_empty() {
            output.push_str("  # Kernel & Memory Protection Matrix\n");
            output.push_str("  boot.kernel.sysctl = {\n");
            for s in &sysctl_lines {
                output.push_str(s);
                output.push('\n');
            }
            output.push_str("  };\n\n");
        }

        if !kernel_params.is_empty() {
            output.push_str("  # Unified Hardened Kernel Parameters\n");
            output.push_str("  boot.kernelParams = [\n");
            for p in &kernel_params {
                output.push_str(&format!("    \"{}\"\n", p));
            }
            output.push_str("  ];\n\n");
        }

        if !blacklisted_modules.is_empty() {
            output.push_str("  # Blacklisted Vulnerable & Legacy Kernel Modules\n");
            output.push_str("  boot.blacklistedKernelModules = [\n");
            for m in &blacklisted_modules {
                output.push_str(&format!("    \"{}\"\n", m));
            }
            output.push_str("  ];\n\n");
        }

        if !raw_blocks.is_empty() {
            output.push_str("  # System, Security & Network Hardening Declarations\n");
            for block in &raw_blocks {
                output.push_str(block);
                output.push_str("\n\n");
            }
        }

        output.push_str("}\n");
        (output, sysctl_count, total_declarations)
    }
}
