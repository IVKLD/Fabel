use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct SshChecker;

#[async_trait]
impl Checker for SshChecker {
    fn domain(&self) -> &'static str {
        "SSH Hardening & Cryptographic Host Keys"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. OpenSSH Server Daemon Configuration
        let sshd_path = "/etc/ssh/sshd_config";
        if Path::new(sshd_path).exists() {
            let content = fs::read_to_string(sshd_path).unwrap_or_default();
            let mut misconfigs = Vec::new();

            let mut pw_auth = false;
            let mut root_login = false;
            let mut x11_fwd = false;

            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.is_empty() {
                    continue;
                }

                let lower = trimmed.to_lowercase();
                if lower.starts_with("passwordauthentication") && lower.contains("yes") {
                    pw_auth = true;
                    misconfigs
                        .push("PasswordAuthentication yes (brute-force exposure)".to_string());
                }
                if lower.starts_with("permitrootlogin")
                    && (lower.contains("yes") || lower.ends_with(" yes"))
                {
                    root_login = true;
                    misconfigs
                        .push("PermitRootLogin yes (direct root brute-force risk)".to_string());
                }
                if lower.starts_with("x11forwarding") && lower.contains("yes") {
                    x11_fwd = true;
                    misconfigs.push("X11Forwarding yes (X11 client hijacking risk)".to_string());
                }
            }

            let failed = pw_auth || root_login || x11_fwd;
            findings.push(Finding {
                domain: self.domain(),
                check_id: "SSH_SERVER_CONFIG".to_string(),
                title: "OpenSSH Daemon Configuration (/etc/ssh/sshd_config)".to_string(),
                severity: Severity::High,
                status: if failed { Status::Fail } else { Status::Pass },
                description: if failed {
                    format!("Detected {} insecure directives in OpenSSH server configuration", misconfigs.len())
                } else {
                    "OpenSSH server adheres to hardening best practices (keys-only, root login restricted, X11 forwarding disabled)".to_string()
                },
                items: misconfigs,
                nixos_fix: if failed {
                    Some("services.openssh.settings = {\n  PasswordAuthentication = false;\n  PermitRootLogin = \"no\";\n  X11Forwarding = false;\n};".to_string())
                } else {
                    None
                },
                doc_url: Some("https://man7.org/linux/man-pages/man5/sshd_config.5.html"),
            });
        } else {
            findings.push(Finding {
                domain: self.domain(),
                check_id: "SSH_SERVER_CONFIG".to_string(),
                title: "OpenSSH Daemon Configuration (/etc/ssh/sshd_config)".to_string(),
                severity: Severity::Info,
                status: Status::Pass,
                description: "OpenSSH server daemon is not active or not configured (no attack surface exposed)".to_string(),
                items: Vec::new(),
                nixos_fix: None,
                doc_url: Some("https://man7.org/linux/man-pages/man5/sshd_config.5.html"),
            });
        }

        // 2. SSH Host Key Cryptographic Strength
        let mut weak_host_keys = Vec::new();
        let mut modern_host_keys = Vec::new();
        if Path::new("/etc/ssh/ssh_host_dsa_key").exists()
            || Path::new("/etc/ssh/ssh_host_dsa_key.pub").exists()
        {
            weak_host_keys
                .push("Legacy DSA host key present (/etc/ssh/ssh_host_dsa_key)".to_string());
        }
        if Path::new("/etc/ssh/ssh_host_ed25519_key").exists() {
            modern_host_keys.push("Ed25519 elliptic curve host key active".to_string());
        }
        if Path::new("/etc/ssh/ssh_host_rsa_key").exists() {
            modern_host_keys.push("RSA host key active".to_string());
        }
        let has_weak_host = !weak_host_keys.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "SSH_HOST_KEYS_STRENGTH".to_string(),
            title: "OpenSSH Host Keys Cryptographic Strength".to_string(),
            severity: Severity::High,
            status: if has_weak_host { Status::Fail } else { Status::Pass },
            description: if has_weak_host {
                format!("Detected {} obsolete or weak host keys", weak_host_keys.len())
            } else if !modern_host_keys.is_empty() {
                format!("Modern cryptographic host keys configured ({})", modern_host_keys.join(", "))
            } else {
                "No SSH host keys found (server daemon disabled)".to_string()
            },
            items: weak_host_keys,
            nixos_fix: if has_weak_host {
                Some("services.openssh.hostKeys = [\n  { path = \"/etc/ssh/ssh_host_ed25519_key\"; type = \"ed25519\"; }\n];".to_string())
            } else {
                None
            },
            doc_url: Some("https://infosec.mozilla.org/guidelines/openssh"),
        });

        // 2. SSH User Authorized Keys & Permissions Audit
        let mut key_candidates = Vec::new();
        if let Ok(home) = env::var("HOME") {
            key_candidates.push(format!("{}/.ssh/authorized_keys", home));
        }
        key_candidates.push("/root/.ssh/authorized_keys".to_string());
        key_candidates.push("/etc/ssh/authorized_keys.d/root".to_string());

        let mut weak_keys = Vec::new();
        let mut insecure_perms = Vec::new();

        for key_file in key_candidates {
            let p = Path::new(&key_file);
            if p.exists() {
                if let Ok(meta) = fs::metadata(p) {
                    let mode = meta.permissions().mode() & 0o777;
                    if (mode & 0o077) != 0 {
                        insecure_perms.push(format!(
                            "{} mode {:o} (group/other writable)",
                            key_file, mode
                        ));
                    }
                }

                if let Ok(content) = fs::read_to_string(p) {
                    for line in content.lines() {
                        let t = line.trim();
                        if t.starts_with("ssh-dss") {
                            weak_keys.push(format!("{}: obsolete DSA key found", key_file));
                        } else if t.starts_with("ssh-rsa") && t.contains("1024") {
                            weak_keys
                                .push(format!("{}: legacy weak 1024-bit RSA key found", key_file));
                        }
                    }
                }
            }
        }

        let key_issues = weak_keys.len() + insecure_perms.len();
        let mut all_items = insecure_perms;
        all_items.extend(weak_keys);

        findings.push(Finding {
            domain: self.domain(),
            check_id: "SSH_AUTHORIZED_KEYS_INTEGRITY".to_string(),
            title: "SSH Authorized Keys File Permissions & Weak Algorithms".to_string(),
            severity: Severity::High,
            status: if key_issues == 0 { Status::Pass } else { Status::Fail },
            description: if key_issues == 0 {
                "User authorized_keys files have secure permissions and modern cryptographic algorithms".to_string()
            } else {
                format!("Detected {} security issues in SSH authorized_keys files", key_issues)
            },
            items: all_items,
            nixos_fix: if key_issues > 0 {
                Some("# Enforce strict permissions and replace with Ed25519 keys:\n# chmod 600 ~/.ssh/authorized_keys".to_string())
            } else {
                None
            },
            doc_url: Some("https://man7.org/linux/man-pages/man8/sshd.8.html"),
        });

        findings
    }
}
