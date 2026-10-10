use crate::types::{is_root, Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::env;
use std::fs;
use std::path::Path;

struct StealthRule {
    check_id: &'static str,
    title: &'static str,
    path: &'static str,
    expected_val: Option<&'static str>,
    severity: Severity,
    desc_pass: &'static str,
    desc_fail: &'static str,
    fix: &'static str,
    doc_url: &'static str,
}

const STEALTH_TABLE: &[StealthRule] = &[
    StealthRule {
        check_id: "STEALTH_BPF_UNPRIV",
        title: "Unprivileged eBPF Execution Hardening",
        path: "/proc/sys/kernel/unprivileged_bpf_disabled",
        expected_val: Some("1"),
        severity: Severity::High,
        desc_pass: "Unprivileged eBPF is disabled (mitigating local ring0 kernel exploitation)",
        desc_fail: "Unprivileged eBPF enabled; unprivileged users can load BPF bytecode into kernel",
        fix: "boot.kernel.sysctl.\"kernel.unprivileged_bpf_disabled\" = 1;",
        doc_url: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#unprivileged-bpf-disabled",
    },
    StealthRule {
        check_id: "STEALTH_GEOCLUE",
        title: "Ambient Wi-Fi Geolocation Tracking (Geoclue)",
        path: "/var/lib/geoclue",
        expected_val: None,
        severity: Severity::Low,
        desc_pass: "Geoclue ambient positioning service disabled",
        desc_fail: "Geoclue service active; Wi-Fi BSSID beacons scanned and leaked to Mozilla/Google location APIs",
        fix: "services.geoclue2.enable = false;",
        doc_url: "https://gitlab.freedesktop.org/geoclue/geoclue/-/wikis/home",
    },
];

pub struct StealthChecker;

#[async_trait]
impl Checker for StealthChecker {
    fn domain(&self) -> &'static str {
        "Stealth Persistence & Kernel Subsystems"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Table-driven checks
        for rule in STEALTH_TABLE {
            if let Some(expected) = rule.expected_val {
                if Path::new(rule.path).exists() {
                    let val = fs::read_to_string(rule.path)
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    let passed = val == expected;
                    findings.push(Finding {
                        domain: self.domain(),
                        check_id: rule.check_id.to_string(),
                        title: rule.title.to_string(),
                        severity: rule.severity,
                        status: if passed { Status::Pass } else { Status::Fail },
                        description: if passed {
                            rule.desc_pass.to_string()
                        } else {
                            format!(
                                "{} (current: '{}', expected: '{}')",
                                rule.desc_fail, val, expected
                            )
                        },
                        items: Vec::new(),
                        nixos_fix: if passed {
                            None
                        } else {
                            Some(rule.fix.to_string())
                        },
                        doc_url: Some(rule.doc_url),
                    });
                }
            } else {
                let exists = Path::new(rule.path).exists();
                findings.push(Finding {
                    domain: self.domain(),
                    check_id: rule.check_id.to_string(),
                    title: rule.title.to_string(),
                    severity: rule.severity,
                    status: if !exists { Status::Pass } else { Status::Warn },
                    description: if !exists {
                        rule.desc_pass.to_string()
                    } else {
                        rule.desc_fail.to_string()
                    },
                    items: Vec::new(),
                    nixos_fix: if exists {
                        Some(rule.fix.to_string())
                    } else {
                        None
                    },
                    doc_url: Some(rule.doc_url),
                });
            }
        }

        // 2. eBPF Loaded Programs Inspection (Requires Root)
        if is_root() {
            let mut active_bpf_progs = Vec::new();
            if let Ok(entries) = fs::read_dir("/sys/fs/bpf") {
                for entry in entries.flatten() {
                    active_bpf_progs.push(entry.file_name().to_string_lossy().to_string());
                }
            }
            findings.push(Finding {
                domain: self.domain(),
                check_id: "STEALTH_BPF_PINNED_PROGS".to_string(),
                title: "Pinned Kernel eBPF Programs (/sys/fs/bpf)".to_string(),
                severity: Severity::Medium,
                status: Status::Pass,
                description: format!(
                    "Audit of pinned BPF objects complete ({} objects)",
                    active_bpf_progs.len()
                ),
                items: active_bpf_progs,
                nixos_fix: None,
                doc_url: Some("https://ebpf.io/what-is-ebpf/"),
            });
        } else {
            findings.push(Finding {
                domain: self.domain(),
                check_id: "STEALTH_BPF_PINNED_PROGS".to_string(),
                title: "Pinned Kernel eBPF Programs (/sys/fs/bpf)".to_string(),
                severity: Severity::Medium,
                status: Status::Skipped {
                    reason: "cap_sys_admin / root required to query pinned BPF objects".to_string(),
                },
                description: "Skipping privileged BPF map and program descriptor audit".to_string(),
                items: Vec::new(),
                nixos_fix: None,
                doc_url: Some("https://ebpf.io/what-is-ebpf/"),
            });
        }

        // 3. X11 vs Wayland Display Protocol Snooping Audit
        let session_type = env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "unknown".to_string());
        let is_x11 = session_type.to_lowercase() == "x11";
        findings.push(Finding {
            domain: self.domain(),
            check_id: "STEALTH_DISPLAY_PROTOCOL".to_string(),
            title: "Display Protocol Security (X11 vs Wayland)".to_string(),
            severity: Severity::High,
            status: if is_x11 { Status::Warn } else { Status::Pass },
            description: if is_x11 {
                "Session runs on X11: arbitrary keylogging and screen snooping possible between unprivileged GUI apps (no client isolation)".to_string()
            } else {
                format!("Session runs on modern isolated protocol (XDG_SESSION_TYPE={})", session_type)
            },
            items: Vec::new(),
            nixos_fix: if is_x11 {
                Some("# Migrate window manager / desktop environment to Wayland:\nservices.xserver.displayManager.gdm.wayland = true;".to_string())
            } else {
                None
            },
            doc_url: Some("https://theinvisiblethings.blogspot.com/2011/04/linux-security-circus-part-side-channel.html"),
        });

        // 4. NTP / NTS Time Security Check
        let mut nts_enabled = false;
        let mut time_service_found = false;

        if let Ok(timesyncd) = fs::read_to_string("/etc/systemd/timesyncd.conf") {
            time_service_found = true;
            if timesyncd.contains("NTS=yes") || timesyncd.contains("NTS=true") {
                nts_enabled = true;
            }
        }

        if let Ok(chrony) = fs::read_to_string("/etc/chrony.conf") {
            time_service_found = true;
            if chrony.contains("nts") {
                nts_enabled = true;
            }
        }

        findings.push(Finding {
            domain: self.domain(),
            check_id: "STEALTH_NTP_NTS_TIME".to_string(),
            title: "Network Time Security (NTP vs NTS Cryptographic Binding)".to_string(),
            severity: Severity::Medium,
            status: if nts_enabled { Status::Pass } else { Status::Warn },
            description: if nts_enabled {
                "Network Time Security (NTS) authenticated time synchronization active".to_string()
            } else if time_service_found {
                "Plaintext UDP:123 NTP in use without NTS (Network Time Security) — vulnerable to time manipulation & TLS/HSTS bypass".to_string()
            } else {
                "No custom NTS-secured time synchronization daemon configured (using system defaults)".to_string()
            },
            items: Vec::new(),
            nixos_fix: if !nts_enabled {
                Some("services.chrony.enable = true;\nservices.chrony.extraConfig = \"\"\"\nserver time.cloudflare.com iburst nts\n\"\"\";".to_string())
            } else {
                None
            },
            doc_url: Some("https://datatracker.ietf.org/doc/html/rfc8915"),
        });

        findings
    }
}
