use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct IntegrityChecker;

#[async_trait]
impl Checker for IntegrityChecker {
    fn domain(&self) -> &'static str {
        "Rootkit, Persistence & Memory Integrity"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Dynamic Linker Hijacking (/etc/ld.so.preload)
        let preload_path = "/etc/ld.so.preload";
        if Path::new(preload_path).exists() {
            let content = fs::read_to_string(preload_path).unwrap_or_default();
            let non_empty = !content.trim().is_empty();
            let entries: Vec<String> = content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|s| s.to_string())
                .collect();
            findings.push(Finding {
                domain: self.domain(),
                check_id: "ROOTKIT_LD_SO_PRELOAD".to_string(),
                title: "Dynamic Linker Preload Persistence".to_string(),
                severity: Severity::Critical,
                status: if non_empty {
                    Status::Fail
                } else {
                    Status::Pass
                },
                description: if non_empty {
                    format!(
                        "Found {} active preload injection library paths",
                        entries.len()
                    )
                } else {
                    format!("{} is empty", preload_path)
                },
                items: entries,
                nixos_fix: Some("environment.etc.\"ld.so.preload\".text = \"\";".to_string()),
                doc_url: Some("https://man7.org/linux/man-pages/man8/ld.so.8.html"),
            });
        } else {
            findings.push(Finding {
                domain: self.domain(),
                check_id: "ROOTKIT_LD_SO_PRELOAD".to_string(),
                title: "Dynamic Linker Preload File".to_string(),
                severity: Severity::Info,
                status: Status::Pass,
                description: "/etc/ld.so.preload is not present".to_string(),
                items: Vec::new(),
                nixos_fix: None,
                doc_url: Some("https://man7.org/linux/man-pages/man8/ld.so.8.html"),
            });
        }

        // 2. Hidden Processes Cross-Check (/proc entry enumeration vs. signal 0 probe)
        let mut proc_pids = HashSet::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<i32>() {
                        proc_pids.insert(pid);
                    }
                }
            }
        }

        let mut hidden_pids = Vec::new();
        for pid in 1..2048 {
            let exists_via_kill = unsafe { libc::kill(pid, 0) == 0 };
            if exists_via_kill && !proc_pids.contains(&pid) {
                hidden_pids.push(format!("PID {}", pid));
            }
        }

        let hidden_count = hidden_pids.len();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "ROOTKIT_HIDDEN_PROCS".to_string(),
            title: "Hidden Process Cross-Check (/proc vs kill-probe)".to_string(),
            severity: Severity::Critical,
            status: if hidden_pids.is_empty() {
                Status::Pass
            } else {
                Status::Fail
            },
            description: if hidden_pids.is_empty() {
                "No process hiding detected in queried PID space".to_string()
            } else {
                format!(
                    "Detected {} anomalous hidden processes responding to signals",
                    hidden_count
                )
            },
            items: hidden_pids,
            nixos_fix: None,
            doc_url: Some("https://man7.org/linux/man-pages/man2/kill.2.html"),
        });

        // 3. Tainted Kernel Analysis
        if let Ok(tainted_str) = fs::read_to_string("/proc/sys/kernel/tainted") {
            let taint_val: u32 = tainted_str.trim().parse().unwrap_or(0);
            findings.push(Finding {
                domain: self.domain(),
                check_id: "KERNEL_TAINT".to_string(),
                title: "Kernel Taint Status".to_string(),
                severity: Severity::High,
                status: if taint_val == 0 {
                    Status::Pass
                } else {
                    Status::Warn
                },
                description: format!("Kernel taint bitmask: {} (0 means untainted)", taint_val),
                items: Vec::new(),
                nixos_fix: if taint_val != 0 {
                    Some(
                        "boot.kernelModules = []; # Investigate out-of-tree or proprietary drivers"
                            .to_string(),
                    )
                } else {
                    None
                },
                doc_url: Some(
                    "https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html",
                ),
            });
        }

        // 4. Fileless Malware & Executable Anon Memory / memfd_create
        let mut suspicious_memory_pids = Vec::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<i32>() {
                        let maps_path = format!("/proc/{}/maps", pid);
                        if let Ok(maps) = fs::read_to_string(&maps_path) {
                            for line in maps.lines() {
                                if (line.contains(" r-xp ") || line.contains(" rwxp "))
                                    && (line.contains("/memfd:") || line.contains("(deleted)"))
                                {
                                    let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                                        .unwrap_or_else(|_| "unknown".to_string())
                                        .trim()
                                        .to_string();
                                    suspicious_memory_pids.push(format!("PID {} ({})", pid, comm));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        let fileless_count = suspicious_memory_pids.len();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "MEMORY_FILELESS_EXEC".to_string(),
            title: "Fileless In-Memory Execution (memfd / deleted r-xp)".to_string(),
            severity: Severity::Critical,
            status: if suspicious_memory_pids.is_empty() {
                Status::Pass
            } else {
                Status::Fail
            },
            description: if suspicious_memory_pids.is_empty() {
                "No suspicious memfd: or deleted executable memory mappings found".to_string()
            } else {
                format!(
                    "Detected {} processes with suspicious executable anonymous memory",
                    fileless_count
                )
            },
            items: suspicious_memory_pids,
            nixos_fix: None,
            doc_url: Some("https://man7.org/linux/man-pages/man2/memfd_create.2.html"),
        });

        // 5. PATH Hijacking: Check for world-writable directories in PATH
        if let Ok(path_var) = env::var("PATH") {
            let mut insecure_dirs = Vec::new();
            for dir in path_var.split(':') {
                if dir.is_empty() {
                    continue;
                }
                if let Ok(meta) = fs::metadata(dir) {
                    let mode = meta.permissions().mode();
                    if (mode & 0o002) != 0 {
                        insecure_dirs.push(dir.to_string());
                    }
                }
            }

            let path_vuln_count = insecure_dirs.len();
            findings.push(Finding {
                domain: self.domain(),
                check_id: "ENV_PATH_HIJACK".to_string(),
                title: "PATH World-Writable Directories".to_string(),
                severity: Severity::High,
                status: if insecure_dirs.is_empty() { Status::Pass } else { Status::Fail },
                description: if insecure_dirs.is_empty() {
                    "No world-writable directories in PATH".to_string()
                } else {
                    format!("Detected {} world-writable directories in PATH", path_vuln_count)
                },
                items: insecure_dirs,
                nixos_fix: Some("environment.variables.PATH = lib.mkForce \"/run/wrappers/bin:/run/current-system/sw/bin\";".to_string()),
                doc_url: Some("https://man7.org/linux/man-pages/man7/environ.7.html"),
            });
        }

        findings
    }
}
