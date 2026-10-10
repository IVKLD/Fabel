use crate::types::{is_root, Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct AccessChecker;

impl AccessChecker {
    fn scan_suid_in_dir(&self, dir: &Path, acc: &mut Vec<String>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let p = path.to_string_lossy();
                if p.starts_with("/nix/store")
                    || p.starts_with("/proc")
                    || p.starts_with("/sys")
                    || p.starts_with("/dev")
                    || p.contains("/.local/share/containers/storage")
                    || p.contains("/docker/overlay2")
                {
                    continue;
                }

                if let Ok(meta) = entry.metadata() {
                    if meta.is_dir() {
                        self.scan_suid_in_dir(&path, acc);
                    } else if meta.is_file() {
                        let mode = meta.permissions().mode();
                        if (mode & 0o4000) != 0 || (mode & 0o2000) != 0 {
                            let p_str = p.to_string();
                            if !p_str.starts_with("/run/wrappers/bin")
                                && !p_str.starts_with("/nix/store")
                            {
                                acc.push(p_str);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Checker for AccessChecker {
    fn domain(&self) -> &'static str {
        "Privileges, Access Control & Accounts"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. SUID/SGID Audit outside managed wrappers
        let mut untracked_suid = Vec::new();
        for candidate in &["/tmp", "/var/tmp", "/home", "/root"] {
            let p = Path::new(candidate);
            if p.exists() {
                self.scan_suid_in_dir(p, &mut untracked_suid);
            }
        }

        let suid_count = untracked_suid.len();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "ACCESS_SUID_UNMANAGED".to_string(),
            title: "Unmanaged SUID/SGID Binaries".to_string(),
            severity: Severity::Critical,
            status: if untracked_suid.is_empty() { Status::Pass } else { Status::Fail },
            description: if untracked_suid.is_empty() {
                "No untracked SUID/SGID binaries outside /run/wrappers and /nix/store".to_string()
            } else {
                format!("Detected {} untracked SUID/SGID binaries outside managed store/wrappers", suid_count)
            },
            items: untracked_suid,
            nixos_fix: Some("# Use declarative NixOS wrappers instead of raw SUID:\nsecurity.wrappers = {\n  # Define wrappers declaratively\n};".to_string()),
            doc_url: Some("https://man7.org/linux/man-pages/man7/capabilities.7.html"),
        });

        // 2. /etc/passwd UID 0 Cross-Check
        if let Ok(passwd_content) = fs::read_to_string("/etc/passwd") {
            let mut uid_zero_users = Vec::new();
            for line in passwd_content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 && parts[2] == "0" && parts[0] != "root" {
                    uid_zero_users.push(parts[0].to_string());
                }
            }

            let uid_count = uid_zero_users.len();
            findings.push(Finding {
                domain: self.domain(),
                check_id: "ACCESS_UID_ZERO".to_string(),
                title: "Superuser Accounts with UID 0".to_string(),
                severity: Severity::Critical,
                status: if uid_zero_users.is_empty() {
                    Status::Pass
                } else {
                    Status::Fail
                },
                description: if uid_zero_users.is_empty() {
                    "Only 'root' holds UID 0".to_string()
                } else {
                    format!("Detected {} unauthorized accounts holding UID 0", uid_count)
                },
                items: uid_zero_users,
                nixos_fix: Some(
                    "# Ensure strict declarative user management:\nusers.mutableUsers = false;"
                        .to_string(),
                ),
                doc_url: Some("https://man7.org/linux/man-pages/man5/passwd.5.html"),
            });
        }

        // 3. /etc/shadow Permissions & Password Hashes
        let shadow_path = "/etc/shadow";
        if Path::new(shadow_path).exists() {
            if is_root() {
                if let Ok(meta) = fs::metadata(shadow_path) {
                    let mode = meta.permissions().mode() & 0o777;
                    let secure_perms = mode == 0o000 || mode == 0o400 || mode == 0o600;
                    findings.push(Finding {
                        domain: self.domain(),
                        check_id: "ACCESS_SHADOW_PERMS".to_string(),
                        title: "/etc/shadow File Mode".to_string(),
                        severity: Severity::High,
                        status: if secure_perms {
                            Status::Pass
                        } else {
                            Status::Fail
                        },
                        description: format!(
                            "Permissions: {:o} (expected 0000, 0400 or 0600)",
                            mode
                        ),
                        items: Vec::new(),
                        nixos_fix: Some(
                            "# Managed by NixOS activation scripts automatically".to_string(),
                        ),
                        doc_url: Some("https://man7.org/linux/man-pages/man5/shadow.5.html"),
                    });
                }

                if let Ok(shadow_content) = fs::read_to_string(shadow_path) {
                    let mut empty_passwords = Vec::new();
                    for line in shadow_content.lines() {
                        let parts: Vec<&str> = line.split(':').collect();
                        if parts.len() >= 2 && parts[1].is_empty() {
                            empty_passwords.push(parts[0].to_string());
                        }
                    }

                    let empty_count = empty_passwords.len();
                    findings.push(Finding {
                        domain: self.domain(),
                        check_id: "ACCESS_EMPTY_PASSWORDS".to_string(),
                        title: "Empty Password Hashes in /etc/shadow".to_string(),
                        severity: Severity::Critical,
                        status: if empty_passwords.is_empty() { Status::Pass } else { Status::Fail },
                        description: if empty_passwords.is_empty() {
                            "No accounts with blank passwords".to_string()
                        } else {
                            format!("Found {} accounts with empty password hashes in /etc/shadow", empty_count)
                        },
                        items: empty_passwords,
                        nixos_fix: Some("users.mutableUsers = false;\nusers.users.<name>.initialHashedPassword = \"...\";".to_string()),
                        doc_url: Some("https://man7.org/linux/man-pages/man5/shadow.5.html"),
                    });
                }
            } else {
                findings.push(Finding {
                    domain: self.domain(),
                    check_id: "ACCESS_SHADOW_PERMS".to_string(),
                    title: "/etc/shadow Audit".to_string(),
                    severity: Severity::High,
                    status: Status::Skipped {
                        reason: "Root privilege required to read shadow file".to_string(),
                    },
                    description: "Skipping /etc/shadow audit for unprivileged user".to_string(),
                    items: Vec::new(),
                    nixos_fix: None,
                    doc_url: Some("https://man7.org/linux/man-pages/man5/shadow.5.html"),
                });
            }
        }

        // 4. Sudoers NOPASSWD Escalation Audit
        let sudoers_file = "/etc/sudoers";
        if Path::new(sudoers_file).exists() {
            if let Ok(content) = fs::read_to_string(sudoers_file) {
                let has_nopasswd = content.lines().any(|l| {
                    let trim = l.trim();
                    !trim.starts_with('#') && trim.contains("NOPASSWD: ALL")
                });

                findings.push(Finding {
                    domain: self.domain(),
                    check_id: "ACCESS_SUDO_NOPASSWD".to_string(),
                    title: "Sudoers NOPASSWD: ALL Escalation".to_string(),
                    severity: Severity::High,
                    status: if has_nopasswd {
                        Status::Fail
                    } else {
                        Status::Pass
                    },
                    description: if has_nopasswd {
                        "Found unauthenticated NOPASSWD: ALL directive in /etc/sudoers"
                    } else {
                        "No global NOPASSWD directives present"
                    }
                    .to_string(),
                    items: Vec::new(),
                    nixos_fix: if has_nopasswd {
                        Some("security.sudo.wheelNeedsPassword = true;".to_string())
                    } else {
                        None
                    },
                    doc_url: Some("https://man7.org/linux/man-pages/man5/sudoers.5.html"),
                });
            }
        }

        findings
    }
}
