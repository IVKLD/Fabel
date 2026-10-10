use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::fs;
use std::path::Path;

pub struct HardwareCpuChecker;

#[async_trait]
impl Checker for HardwareCpuChecker {
    fn domain(&self) -> &'static str {
        "Hardware, CPU Microcode & Speculative Mitigations"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Kernel command-line mitigations check
        let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
        let mitigations_disabled = cmdline.contains("mitigations=off");

        findings.push(Finding {
            domain: self.domain(),
            check_id: "HW_CPU_MITIGATIONS_PARAM".to_string(),
            title: "Kernel Speculative Execution Mitigations Command-Line".to_string(),
            severity: Severity::Critical,
            status: if mitigations_disabled { Status::Fail } else { Status::Pass },
            description: if mitigations_disabled {
                "CRITICAL: 'mitigations=off' present in boot cmdline! All hardware CPU mitigations are disabled".to_string()
            } else {
                "CPU speculative execution hardware mitigations are active (no 'mitigations=off' override)".to_string()
            },
            items: Vec::new(),
            nixos_fix: if mitigations_disabled {
                Some("boot.kernelParams = [ \"mitigations=auto,nosmt\" ];".to_string())
            } else {
                None
            },
            doc_url: Some("https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html"),
        });

        // 2. Sysfs CPU vulnerabilities table-driven scan
        let vuln_dir = "/sys/devices/system/cpu/vulnerabilities";
        if Path::new(vuln_dir).exists() {
            let mut unmitigated = Vec::new();
            let mut mitigated_count = 0;

            if let Ok(entries) = fs::read_dir(vuln_dir) {
                for entry in entries.flatten() {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        let trimmed = content.trim().to_string();
                        if trimmed.starts_with("Vulnerable") {
                            unmitigated.push(format!("{}: {}", file_name, trimmed));
                        } else {
                            mitigated_count += 1;
                        }
                    }
                }
            }

            let has_vuln = !unmitigated.is_empty();
            findings.push(Finding {
                domain: self.domain(),
                check_id: "HW_CPU_VULNERABILITIES".to_string(),
                title: "CPU Hardware Vulnerabilities (/sys/devices/system/cpu/vulnerabilities)"
                    .to_string(),
                severity: if has_vuln {
                    Severity::High
                } else {
                    Severity::Info
                },
                status: if has_vuln { Status::Warn } else { Status::Pass },
                description: if has_vuln {
                    format!(
                        "Detected {} CPU vulnerabilities reporting Vulnerable state",
                        unmitigated.len()
                    )
                } else {
                    format!(
                        "All {} probed hardware CPU attack vectors are mitigated or not affected",
                        mitigated_count
                    )
                },
                items: unmitigated,
                nixos_fix: if has_vuln {
                    Some("boot.kernelParams = [ \"mitigations=auto,nosmt\" ];".to_string())
                } else {
                    None
                },
                doc_url: Some(
                    "https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html",
                ),
            });
        }

        // 3. CPU Microcode Audit
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            let is_intel = cpuinfo.contains("GenuineIntel");
            let is_amd = cpuinfo.contains("AuthenticAMD");
            let mut microcode_ver = "unknown".to_string();

            for line in cpuinfo.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("microcode") {
                    if let Some((_, val)) = trimmed.split_once(':') {
                        microcode_ver = val.trim().to_string();
                        break;
                    }
                }
            }

            findings.push(Finding {
                domain: self.domain(),
                check_id: "HW_CPU_MICROCODE".to_string(),
                title: "CPU Microcode Firmware Level".to_string(),
                severity: Severity::Medium,
                status: Status::Pass,
                description: format!(
                    "Microcode revision: {} ({})",
                    microcode_ver,
                    if is_amd {
                        "AMD"
                    } else if is_intel {
                        "Intel"
                    } else {
                        "Generic"
                    }
                ),
                items: Vec::new(),
                nixos_fix: if is_intel {
                    Some("hardware.cpu.intel.updateMicrocode = true;".to_string())
                } else if is_amd {
                    Some("hardware.cpu.amd.updateMicrocode = true;".to_string())
                } else {
                    None
                },
                doc_url: Some("https://nixos.wiki/wiki/Microcode"),
            });
        }

        findings
    }
}
