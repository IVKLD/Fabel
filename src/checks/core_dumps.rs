use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::fs;
use std::path::Path;

pub struct CoreDumpsChecker;

#[async_trait]
impl Checker for CoreDumpsChecker {
    fn domain(&self) -> &'static str {
        "Memory Dump Security & Sensitive Secret Storage"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. fs.suid_dumpable
        let suid_dumpable_path = "/proc/sys/fs/suid_dumpable";
        if Path::new(suid_dumpable_path).exists() {
            let val = fs::read_to_string(suid_dumpable_path)
                .unwrap_or_default()
                .trim()
                .to_string();

            let secure = val == "0";
            findings.push(Finding {
                domain: self.domain(),
                check_id: "MEM_SUID_DUMPABLE".to_string(),
                title: "SUID Core Dump Memory Hardening (fs.suid_dumpable)".to_string(),
                severity: Severity::High,
                status: if secure { Status::Pass } else { Status::Fail },
                description: if secure {
                    "fs.suid_dumpable = 0: privileged SUID processes cannot produce core dumps containing memory secrets".to_string()
                } else {
                    format!("fs.suid_dumpable is '{}' (expected '0'): core dumps of setuid binaries may leak memory secrets or credentials", val)
                },
                items: Vec::new(),
                nixos_fix: if secure {
                    None
                } else {
                    Some("boot.kernel.sysctl.\"fs.suid_dumpable\" = 0;".to_string())
                },
                doc_url: Some("https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#suid-dumpable"),
            });
        }

        // 2. systemd-coredump persistence
        let coredump_conf = "/etc/systemd/coredump.conf";
        let mut disabled_or_ephemeral = false;
        if Path::new(coredump_conf).exists() {
            if let Ok(content) = fs::read_to_string(coredump_conf) {
                if content.contains("Storage=none") {
                    disabled_or_ephemeral = true;
                }
            }
        }

        let coredump_dir = "/var/lib/systemd/coredump";
        let has_coredump_spool = Path::new(coredump_dir).exists();

        let passes_coredump = disabled_or_ephemeral || !has_coredump_spool;
        findings.push(Finding {
            domain: self.domain(),
            check_id: "MEM_SYSTEMD_COREDUMP_STORAGE".to_string(),
            title: "Process Core Dump Disk Persistence (systemd-coredump)".to_string(),
            severity: Severity::Medium,
            status: if passes_coredump { Status::Pass } else { Status::Warn },
            description: if passes_coredump {
                "systemd-coredump disk persistence disabled or not spooled to disk".to_string()
            } else {
                "Core dumps are stored on disk (/var/lib/systemd/coredump): crashed browsers, SSH agents, or password managers may persist secrets in RAM dumps".to_string()
            },
            items: Vec::new(),
            nixos_fix: if passes_coredump {
                None
            } else {
                Some("systemd.coredump.enable = false;".to_string())
            },
            doc_url: Some("https://man7.org/linux/man-pages/man5/coredump.conf.5.html"),
        });

        findings
    }
}
