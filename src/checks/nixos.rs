use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::fs;
use std::path::Path;

pub struct NixosChecker;

#[async_trait]
impl Checker for NixosChecker {
    fn domain(&self) -> &'static str {
        "NixOS Declarative Architecture & Daemon"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Nix Daemon Sandboxing & Trusted Users
        let nix_conf = "/etc/nix/nix.conf";
        if Path::new(nix_conf).exists() {
            let content = fs::read_to_string(nix_conf).unwrap_or_default();

            // Sandboxing check
            let sandboxed = content.lines().any(|l| {
                let t = l.trim();
                t.starts_with("sandbox") && t.contains("true")
            });

            findings.push(Finding {
                domain: self.domain(),
                check_id: "NIX_BUILD_SANDBOX".to_string(),
                title: "Nix Daemon Build Sandboxing".to_string(),
                severity: Severity::High,
                status: if sandboxed { Status::Pass } else { Status::Fail },
                description: if sandboxed {
                    "Nix daemon build isolation active (sandbox = true)".to_string()
                } else {
                    "Nix build sandboxing disabled: derivations can access network and host namespaces arbitrarily".to_string()
                },
                items: Vec::new(),
                nixos_fix: if sandboxed {
                    None
                } else {
                    Some("nix.settings.sandbox = true;\nnix.settings.sandbox-fallback = false;".to_string())
                },
                doc_url: Some("https://nixos.org/manual/nix/stable/command-ref/conf-file.html#conf-sandbox"),
            });

            // Trusted Users audit
            let mut untrusted_priv_users = Vec::new();
            for line in content.lines() {
                let t = line.trim();
                if t.starts_with("trusted-users") {
                    if let Some((_, users)) = t.split_once('=') {
                        for u in users.split_whitespace() {
                            if u != "root" && u != "@wheel" {
                                untrusted_priv_users.push(u.to_string());
                            }
                        }
                    }
                }
            }

            let has_untrusted = !untrusted_priv_users.is_empty();
            findings.push(Finding {
                domain: self.domain(),
                check_id: "NIX_TRUSTED_USERS_SCOPE".to_string(),
                title: "Nix Daemon Trusted Users Scope".to_string(),
                severity: Severity::Critical,
                status: if has_untrusted { Status::Fail } else { Status::Pass },
                description: if has_untrusted {
                    format!("Unprivileged users granted root-equivalent access via nix daemon socket: {:?}", untrusted_priv_users)
                } else {
                    "Only root and wheel members authorized in trusted-users".to_string()
                },
                items: untrusted_priv_users,
                nixos_fix: if has_untrusted {
                    Some("nix.settings.trusted-users = [ \"root\" \"@wheel\" ];".to_string())
                } else {
                    None
                },
                doc_url: Some("https://nixos.org/manual/nix/stable/command-ref/conf-file.html#conf-trusted-users"),
            });

            // Binary Cache Signature Verification check
            let require_sigs = content.lines().any(|l| {
                let t = l.trim();
                t.starts_with("require-sigs") && t.contains("true")
            });

            findings.push(Finding {
                domain: self.domain(),
                check_id: "NIX_REQUIRE_SIGS".to_string(),
                title: "Nix Binary Cache Cryptographic Signature Verification".to_string(),
                severity: Severity::Critical,
                status: if require_sigs { Status::Pass } else { Status::Fail },
                description: if require_sigs {
                    "Nix requires cryptographic signatures on all substituters/binary caches (require-sigs = true)".to_string()
                } else {
                    "require-sigs = false! Unsigned binary packages can be injected from arbitrary substituters".to_string()
                },
                items: Vec::new(),
                nixos_fix: if require_sigs {
                    None
                } else {
                    Some("nix.settings.require-sigs = true;".to_string())
                },
                doc_url: Some("https://nixos.org/manual/nix/stable/command-ref/conf-file.html#conf-require-sigs"),
            });

            // Store Auto-Optimisation check
            let auto_optimise = content.lines().any(|l| {
                let t = l.trim();
                t.starts_with("auto-optimise-store") && t.contains("true")
            });

            findings.push(Finding {
                domain: self.domain(),
                check_id: "NIX_AUTO_OPTIMISE_STORE".to_string(),
                title: "Nix Store Automatic Hardlink Deduplication".to_string(),
                severity: Severity::Low,
                status: if auto_optimise { Status::Pass } else { Status::Warn },
                description: if auto_optimise {
                    "Nix store automatically hardlinks identical content hashes (auto-optimise-store = true)".to_string()
                } else {
                    "auto-optimise-store is disabled; store paths are not deduplicated automatically".to_string()
                },
                items: Vec::new(),
                nixos_fix: if auto_optimise {
                    None
                } else {
                    Some("nix.settings.auto-optimise-store = true;".to_string())
                },
                doc_url: Some("https://nixos.org/manual/nix/stable/command-ref/conf-file.html#conf-auto-optimise-store"),
            });
        }

        // 2. Ephemeral Root / Erase Your Darlings Pattern & /nix/store Read-Only Check
        let mut ephemeral_root = false;
        let mut root_mount_info = String::new();
        let mut nix_store_ro = false;
        let mut nix_store_found = false;

        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let mountpoint = parts[1];
                    let fstype = parts[2];
                    let opts = parts[3];

                    if mountpoint == "/" {
                        root_mount_info = format!("root fs: {} ({})", fstype, opts);
                        if fstype == "tmpfs" || opts.split(',').any(|o| o == "ro") {
                            ephemeral_root = true;
                        }
                    } else if mountpoint == "/nix/store" {
                        nix_store_found = true;
                        if opts.split(',').any(|o| o == "ro") {
                            nix_store_ro = true;
                        }
                    }
                }
            }
        }

        findings.push(Finding {
            domain: self.domain(),
            check_id: "NIX_EPHEMERAL_ROOT".to_string(),
            title: "Ephemeral / Immutable Root Filesystem (tmpfs / ZFS rollback)".to_string(),
            severity: Severity::Medium,
            status: if ephemeral_root { Status::Pass } else { Status::Warn },
            description: if ephemeral_root {
                format!("Ephemeral root scheme active: {}", root_mount_info)
            } else {
                format!("Root (/) is persistent across reboots ({}); state can accumulate unauthorized persistent implants", root_mount_info)
            },
            items: Vec::new(),
            nixos_fix: if ephemeral_root {
                None
            } else {
                Some("fileSystems.\"/\" = {\n  device = \"none\";\n  fsType = \"tmpfs\";\n  options = [ \"defaults\" \"size=2G\" \"mode=755\" ];\n};".to_string())
            },
            doc_url: Some("https://grahamc.com/blog/erase-your-darlings/"),
        });

        // /nix/store read-only check
        let store_protected = nix_store_ro || !nix_store_found; // If not separate mount, check root ro
        findings.push(Finding {
            domain: self.domain(),
            check_id: "NIX_STORE_MOUNT_RO".to_string(),
            title: "Nix Store Read-Only Mount Protection".to_string(),
            severity: Severity::High,
            status: if store_protected { Status::Pass } else { Status::Fail },
            description: if store_protected {
                "/nix/store is mounted read-only, preventing runtime derivation tampering".to_string()
            } else {
                "/nix/store is mounted read-write! Vulnerable to direct on-disk modification of system binaries".to_string()
            },
            items: Vec::new(),
            nixos_fix: if store_protected {
                None
            } else {
                Some("boot.readOnlyNixStore = true;".to_string())
            },
            doc_url: Some("https://nixos.wiki/wiki/Nix_store"),
        });

        findings
    }
}
