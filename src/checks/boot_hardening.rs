use crate::types::{is_root, Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::fs;
use std::path::Path;

struct SysctlRule {
    param: &'static str,
    path: &'static str,
    expected: &'static str,
    severity: Severity,
    desc: &'static str,
    fix: &'static str,
    doc_url: &'static str,
}

const SYSCTL_MATRIX: &[SysctlRule] = &[
    SysctlRule {
        param: "kernel.randomize_va_space",
        path: "/proc/sys/kernel/randomize_va_space",
        expected: "2",
        severity: Severity::Critical,
        desc: "Full Address Space Layout Randomization (ASLR)",
        fix: "boot.kernel.sysctl.\"kernel.randomize_va_space\" = 2;",
        doc_url: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#randomize-va-space",
    },
    SysctlRule {
        param: "kernel.kptr_restrict",
        path: "/proc/sys/kernel/kptr_restrict",
        expected: "2",
        severity: Severity::High,
        desc: "Kernel pointers hidden from non-CAP_SYSLOG users",
        fix: "boot.kernel.sysctl.\"kernel.kptr_restrict\" = 2;",
        doc_url: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#kptr-restrict",
    },
    SysctlRule {
        param: "kernel.dmesg_restrict",
        path: "/proc/sys/kernel/dmesg_restrict",
        expected: "1",
        severity: Severity::Medium,
        desc: "Unprivileged access to dmesg restricted",
        fix: "boot.kernel.sysctl.\"kernel.dmesg_restrict\" = 1;",
        doc_url: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#dmesg-restrict",
    },
    SysctlRule {
        param: "kernel.yama.ptrace_scope",
        path: "/proc/sys/kernel/yama/ptrace_scope",
        expected: "2",
        severity: Severity::High,
        desc: "Yama ptrace scope restricts cross-process debugging/injection",
        fix: "boot.kernel.sysctl.\"kernel.yama.ptrace_scope\" = 2;",
        doc_url: "https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html",
    },
    SysctlRule {
        param: "fs.protected_symlinks",
        path: "/proc/sys/fs/protected_symlinks",
        expected: "1",
        severity: Severity::Medium,
        desc: "Protected symlink traversal in world-writable stickies",
        fix: "boot.kernel.sysctl.\"fs.protected_symlinks\" = 1;",
        doc_url: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks",
    },
    SysctlRule {
        param: "fs.protected_hardlinks",
        path: "/proc/sys/fs/protected_hardlinks",
        expected: "1",
        severity: Severity::Medium,
        desc: "Protected hardlink creation against file unauthorized access",
        fix: "boot.kernel.sysctl.\"fs.protected_hardlinks\" = 1;",
        doc_url: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-hardlinks",
    },
    SysctlRule {
        param: "net.ipv4.conf.all.rp_filter",
        path: "/proc/sys/net/ipv4/conf/all/rp_filter",
        expected: "1",
        severity: Severity::High,
        desc: "Strict reverse path filtering prevents IP spoofing",
        fix: "boot.kernel.sysctl.\"net.ipv4.conf.all.rp_filter\" = 1;",
        doc_url: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html#ip-sysctl",
    },
    SysctlRule {
        param: "net.ipv4.conf.default.rp_filter",
        path: "/proc/sys/net/ipv4/conf/default/rp_filter",
        expected: "1",
        severity: Severity::High,
        desc: "Default reverse path filtering on newly created interfaces",
        fix: "boot.kernel.sysctl.\"net.ipv4.conf.default.rp_filter\" = 1;",
        doc_url: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html#ip-sysctl",
    },
    SysctlRule {
        param: "kernel.kexec_load_disabled",
        path: "/proc/sys/kernel/kexec_load_disabled",
        expected: "1",
        severity: Severity::Critical,
        desc: "Disable live in-memory kernel replacement via kexec_load syscall",
        fix: "boot.kernel.sysctl.\"kernel.kexec_load_disabled\" = 1;",
        doc_url: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#kexec-load-disabled",
    },
    SysctlRule {
        param: "net.ipv4.tcp_rfc1337",
        path: "/proc/sys/net/ipv4/tcp_rfc1337",
        expected: "1",
        severity: Severity::Medium,
        desc: "RFC 1337 protection against TCP TIME-WAIT assassination hazards",
        fix: "boot.kernel.sysctl.\"net.ipv4.tcp_rfc1337\" = 1;",
        doc_url: "https://datatracker.ietf.org/doc/html/rfc1337",
    },
    SysctlRule {
        param: "net.ipv4.conf.all.accept_redirects",
        path: "/proc/sys/net/ipv4/conf/all/accept_redirects",
        expected: "0",
        severity: Severity::High,
        desc: "Ignore ICMP redirect packets (mitigate rogue gateway routing table MITM)",
        fix: "boot.kernel.sysctl.\"net.ipv4.conf.all.accept_redirects\" = 0;",
        doc_url: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html",
    },
    SysctlRule {
        param: "net.ipv4.conf.default.accept_redirects",
        path: "/proc/sys/net/ipv4/conf/default/accept_redirects",
        expected: "0",
        severity: Severity::High,
        desc: "Ignore ICMP redirects on newly added network interfaces by default",
        fix: "boot.kernel.sysctl.\"net.ipv4.conf.default.accept_redirects\" = 0;",
        doc_url: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html",
    },
    SysctlRule {
        param: "net.ipv4.conf.all.accept_source_route",
        path: "/proc/sys/net/ipv4/conf/all/accept_source_route",
        expected: "0",
        severity: Severity::High,
        desc: "Reject source routed packets (prevent IP spoofing and bypass routing)",
        fix: "boot.kernel.sysctl.\"net.ipv4.conf.all.accept_source_route\" = 0;",
        doc_url: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html",
    },
    SysctlRule {
        param: "net.ipv4.icmp_echo_ignore_broadcasts",
        path: "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
        expected: "1",
        severity: Severity::Medium,
        desc: "Ignore broadcast ICMP echo requests (mitigate Smurf amplification attacks)",
        fix: "boot.kernel.sysctl.\"net.ipv4.icmp_echo_ignore_broadcasts\" = 1;",
        doc_url: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html",
    },
    SysctlRule {
        param: "fs.protected_regular",
        path: "/proc/sys/fs/protected_regular",
        expected: "2",
        severity: Severity::Medium,
        desc: "Protected writes to regular files in world-writable sticky directories",
        fix: "boot.kernel.sysctl.\"fs.protected_regular\" = 2;",
        doc_url: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-regular",
    },
    SysctlRule {
        param: "fs.protected_fifos",
        path: "/proc/sys/fs/protected_fifos",
        expected: "2",
        severity: Severity::Medium,
        desc: "Protected writes to FIFOs in world-writable sticky directories",
        fix: "boot.kernel.sysctl.\"fs.protected_fifos\" = 2;",
        doc_url: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-fifos",
    },
    SysctlRule {
        param: "net.core.bpf_jit_harden",
        path: "/proc/sys/net/core/bpf_jit_harden",
        expected: "2",
        severity: Severity::High,
        desc: "eBPF JIT constant blinding for unprivileged and privileged programs (anti-JIT-spraying)",
        fix: "boot.kernel.sysctl.\"net.core.bpf_jit_harden\" = 2;",
        doc_url: "https://docs.kernel.org/admin-guide/sysctl/net.html#bpf-jit-harden",
    },
];

pub struct BootHardeningChecker;

#[async_trait]
impl Checker for BootHardeningChecker {
    fn domain(&self) -> &'static str {
        "Boot, Hardware Integrity & Sysctl Matrix"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Unencrypted /boot & ESP Evil Maid Vulnerability Check
        let mut unencrypted_boot = false;
        let mut boot_mount_details = String::new();
        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let mount_point = parts[1];
                    let device = parts[0];
                    let fstype = parts[2];
                    if (mount_point == "/boot"
                        || mount_point == "/efi"
                        || mount_point == "/boot/efi")
                        && fstype == "vfat"
                        && !device.starts_with("/dev/mapper/")
                    {
                        unencrypted_boot = true;
                        boot_mount_details =
                            format!("{} mounted on {} as {}", device, mount_point, fstype);
                        break;
                    }
                }
            }
        }

        findings.push(Finding {
            domain: self.domain(),
            check_id: "BOOT_UNENCRYPTED_STAGE".to_string(),
            title: "Unencrypted /boot & ESP (Evil Maid Attack Exposure)".to_string(),
            severity: Severity::High,
            status: if unencrypted_boot { Status::Warn } else { Status::Pass },
            description: if unencrypted_boot {
                format!("Unencrypted boot partition detected ({}): kernel/initrd subject to physical tampering without measured boot verification", boot_mount_details)
            } else {
                "/boot partition is unified with encrypted root or protected via secure measured boot".to_string()
            },
            items: Vec::new(),
            nixos_fix: if unencrypted_boot {
                Some("# Enable UEFI Secure Boot with Lanzaboote to verify boot stages:\nboot.lanzaboote.enable = true;".to_string())
            } else {
                None
            },
            doc_url: Some("https://github.com/nix-community/lanzaboote/blob/master/docs/QUICK_START.md"),
        });

        // 2. Kernel Lockdown Mode
        let lockdown_path = "/sys/kernel/security/lockdown";
        if Path::new(lockdown_path).exists() {
            let content = fs::read_to_string(lockdown_path).unwrap_or_default();
            let locked = content.contains("[integrity]") || content.contains("[confidentiality]");
            findings.push(Finding {
                domain: self.domain(),
                check_id: "BOOT_KERNEL_LOCKDOWN".to_string(),
                title: "Kernel Lockdown LSM Mode".to_string(),
                severity: Severity::High,
                status: if locked { Status::Pass } else { Status::Fail },
                description: format!("Current kernel lockdown state: {}", content.trim()),
                items: Vec::new(),
                nixos_fix: if locked {
                    None
                } else {
                    Some("boot.kernelParams = [ \"lockdown=integrity\" ];".to_string())
                },
                doc_url: Some("https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html"),
            });
        } else {
            findings.push(Finding {
                domain: self.domain(),
                check_id: "BOOT_KERNEL_LOCKDOWN".to_string(),
                title: "Kernel Lockdown LSM Mode".to_string(),
                severity: Severity::High,
                status: Status::Fail,
                description:
                    "Kernel lockdown interface absent (/sys/kernel/security/lockdown missing)"
                        .to_string(),
                items: Vec::new(),
                nixos_fix: Some("boot.kernelParams = [ \"lockdown=integrity\" ];".to_string()),
                doc_url: Some("https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html"),
            });
        }

        // 3. UEFI Secure Boot & Lanzaboote Status
        let efi_sb = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
        if Path::new(efi_sb).exists() {
            let enabled = fs::read(efi_sb)
                .map(|b| b.last().map(|&x| x == 1).unwrap_or(false))
                .unwrap_or(false);
            findings.push(Finding {
                domain: self.domain(),
                check_id: "BOOT_SECURE_BOOT".to_string(),
                title: "UEFI Secure Boot & Lanzaboote".to_string(),
                severity: Severity::Critical,
                status: if enabled { Status::Pass } else { Status::Fail },
                description: if enabled {
                    "UEFI Secure Boot active and verified".to_string()
                } else {
                    "UEFI Secure Boot is disabled in firmware".to_string()
                },
                items: Vec::new(),
                nixos_fix: if enabled {
                    None
                } else {
                    Some(
                        "# Deploy Lanzaboote for NixOS:\n# boot.lanzaboote.enable = true;"
                            .to_string(),
                    )
                },
                doc_url: Some("https://github.com/nix-community/lanzaboote"),
            });
        } else {
            findings.push(Finding {
                domain: self.domain(),
                check_id: "BOOT_SECURE_BOOT".to_string(),
                title: "UEFI Secure Boot & Lanzaboote".to_string(),
                severity: Severity::High,
                status: Status::Skipped {
                    reason: "EFI efivars not accessible or Legacy BIOS mode".to_string(),
                },
                description: "Cannot read Secure Boot variable from sysfs".to_string(),
                items: Vec::new(),
                nixos_fix: None,
                doc_url: Some("https://github.com/nix-community/lanzaboote"),
            });
        }

        // 4. Sysctl Matrix (Table-Driven)
        for rule in SYSCTL_MATRIX {
            if !is_root() && !Path::new(rule.path).exists() {
                findings.push(Finding {
                    domain: self.domain(),
                    check_id: format!("SYSCTL_{}", rule.param.replace('.', "_").to_uppercase()),
                    title: format!("Sysctl {}", rule.param),
                    severity: rule.severity,
                    status: Status::Skipped {
                        reason: "Root access required to inspect restricted sysctl node"
                            .to_string(),
                    },
                    description: rule.desc.to_string(),
                    items: Vec::new(),
                    nixos_fix: Some(rule.fix.to_string()),
                    doc_url: Some(rule.doc_url),
                });
                continue;
            }

            match fs::read_to_string(rule.path) {
                Ok(val) => {
                    let actual = val.trim();
                    let passed = actual == rule.expected;
                    findings.push(Finding {
                        domain: self.domain(),
                        check_id: format!("SYSCTL_{}", rule.param.replace('.', "_").to_uppercase()),
                        title: format!("Sysctl {}", rule.param),
                        severity: rule.severity,
                        status: if passed { Status::Pass } else { Status::Fail },
                        description: format!(
                            "{} (current: '{}', required: '{}')",
                            rule.desc, actual, rule.expected
                        ),
                        items: Vec::new(),
                        nixos_fix: if passed {
                            None
                        } else {
                            Some(rule.fix.to_string())
                        },
                        doc_url: Some(rule.doc_url),
                    });
                }
                Err(e) => {
                    findings.push(Finding {
                        domain: self.domain(),
                        check_id: format!("SYSCTL_{}", rule.param.replace('.', "_").to_uppercase()),
                        title: format!("Sysctl {}", rule.param),
                        severity: rule.severity,
                        status: Status::Fail,
                        description: format!("Failed reading {}: {}", rule.path, e),
                        items: Vec::new(),
                        nixos_fix: Some(rule.fix.to_string()),
                        doc_url: Some(rule.doc_url),
                    });
                }
            }
        }

        findings
    }
}
