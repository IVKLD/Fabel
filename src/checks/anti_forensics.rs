use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::fs;
use std::path::Path;

pub struct AntiForensicsChecker;

const DANGEROUS_MODULES: &[(&str, &str)] = &[
    ("dccp", "Datagram Congestion Control Protocol (DCCP)"),
    ("sctp", "Stream Control Transmission Protocol (SCTP)"),
    ("rds", "Reliable Datagram Sockets (RDS)"),
    ("tipc", "Transparent Inter-Process Communication (TIPC)"),
    (
        "firewire-core",
        "IEEE 1394 FireWire Direct Memory Access Bus",
    ),
    ("firewire_ohci", "FireWire OHCI Controller Driver"),
];

#[async_trait]
impl Checker for AntiForensicsChecker {
    fn domain(&self) -> &'static str {
        "Digital Forensics Evasion, Anti-Surveillance & RAM Hygiene"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Systemd Journal On-Disk Persistence (Volatile RAM-only journal)
        let journal_dir = "/var/log/journal";
        let has_disk_journal = Path::new(journal_dir).exists()
            && fs::read_dir(journal_dir)
                .map(|mut e| e.next().is_some())
                .unwrap_or(false);

        findings.push(Finding {
            domain: self.domain(),
            check_id: "FORENSIC_JOURNAL_STORAGE".to_string(),
            title: "Systemd Journal On-Disk Forensic Timeline Retention".to_string(),
            severity: Severity::High,
            status: if !has_disk_journal { Status::Pass } else { Status::Warn },
            description: if !has_disk_journal {
                "Journal logs are volatile (stored in RAM only); destroyed upon power-off".to_string()
            } else {
                "Systemd journal stored persistently on disk (/var/log/journal): preserves chronological timeline of boot sessions, USB insertions, network connections".to_string()
            },
            items: Vec::new(),
            nixos_fix: if has_disk_journal {
                Some("services.journald.extraConfig = ''\n  Storage=volatile\n  RuntimeMaxUse=64M\n'';".to_string())
            } else {
                None
            },
            doc_url: Some("https://man7.org/linux/man-pages/man5/journald.conf.5.html"),
        });

        // 2. /proc Mount Isolation (hidepid=2 / invisible)
        let mut hidepid_active = false;
        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[1] == "/proc" {
                    let opts = parts[3];
                    if opts.contains("hidepid=2") || opts.contains("hidepid=invisible") {
                        hidepid_active = true;
                    }
                    break;
                }
            }
        }

        findings.push(Finding {
            domain: self.domain(),
            check_id: "FORENSIC_PROC_HIDEPID".to_string(),
            title: "Process Table Isolation & Arguments Snooping (/proc hidepid)".to_string(),
            severity: Severity::High,
            status: if hidepid_active { Status::Pass } else { Status::Fail },
            description: if hidepid_active {
                "/proc mounted with hidepid: unprivileged processes cannot snoop on foreign PIDs or command-line credentials".to_string()
            } else {
                "/proc mounted without hidepid: any unprivileged local process can inspect all running processes, usernames, and command-line parameters".to_string()
            },
            items: Vec::new(),
            nixos_fix: if hidepid_active {
                None
            } else {
                Some("# Note: security.hideProcessInformation is removed in NixOS on cgroups-v2; process isolation is enforced per-service via systemd (ProtectProc=invisible).".to_string())
            },
            doc_url: Some("https://www.kernel.org/doc/html/latest/filesystems/proc.html#mount-options"),
        });

        // 3. Plaintext Swap / RAM-on-Disk Forensic Leakage
        let mut unencrypted_swaps = Vec::new();
        if let Ok(swaps) = fs::read_to_string("/proc/swaps") {
            for line in swaps.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let dev = parts[0];
                    let stype = parts[1];
                    // zram and dm-crypt devices are considered encrypted/ephemeral
                    let is_safe =
                        dev.contains("zram") || dev.contains("dm-") || dev.contains("mapper");
                    if !is_safe {
                        unencrypted_swaps.push(format!("{} (type: {})", dev, stype));
                    }
                }
            }
        }

        let has_plain_swap = !unencrypted_swaps.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "FORENSIC_SWAP_ENCRYPTION".to_string(),
            title: "Plaintext Swap Partition Memory Leakage".to_string(),
            severity: Severity::Critical,
            status: if !has_plain_swap { Status::Pass } else { Status::Fail },
            description: if !has_plain_swap {
                "All swap spaces use zRAM in-memory compression or encrypted device-mapper devices".to_string()
            } else {
                format!("Detected {} unencrypted swap devices: RAM pages, master keys and plaintext passwords can be flushed to disk", unencrypted_swaps.len())
            },
            items: unencrypted_swaps,
            nixos_fix: if has_plain_swap {
                Some("# Enable zram swap or random disk encryption for swap:\nzramSwap.enable = true;\nswapDevices = [\n  # Add: randomEncryption.enable = true;\n];".to_string())
            } else {
                None
            },
            doc_url: Some("https://nixos.wiki/wiki/Swap"),
        });

        // 4. DHCP Hostname Broadcast Leaks (Option 12)
        let nm_conf_path = "/etc/NetworkManager/NetworkManager.conf";
        let mut dhcp_hostname_disabled = false;
        if Path::new(nm_conf_path).exists() {
            let content = fs::read_to_string(nm_conf_path).unwrap_or_default();
            if content.contains("dhcp-send-hostname=false") {
                dhcp_hostname_disabled = true;
            }
        }

        findings.push(Finding {
            domain: self.domain(),
            check_id: "FORENSIC_DHCP_HOSTNAME_LEAK".to_string(),
            title: "DHCP Hostname Radio & LAN Broadcast Leak (Option 12)".to_string(),
            severity: Severity::Medium,
            status: if dhcp_hostname_disabled { Status::Pass } else { Status::Warn },
            description: if dhcp_hostname_disabled {
                "DHCP hostname broadcast disabled: machine name is not leaked to local network routers".to_string()
            } else {
                "NetworkManager broadcasts machine hostname in plaintext DHCP Option 12 to every connected router / AP".to_string()
            },
            items: Vec::new(),
            nixos_fix: if dhcp_hostname_disabled {
                None
            } else {
                Some("networking.networkmanager.settings.connection.\"ipv4.dhcp-send-hostname\" = false;\nnetworking.networkmanager.settings.connection.\"ipv6.dhcp-send-hostname\" = false;".to_string())
            },
            doc_url: Some("https://networkmanager.dev/docs/api/latest/nm-settings-nmcli.html"),
        });

        // 5. Dangerous & Legacy Network Protocols / FireWire Module Blacklist
        let mut unblacklisted_modules = Vec::new();
        let loaded_modules = fs::read_to_string("/proc/modules").unwrap_or_default();
        let modprobe_conf = fs::read_to_string("/etc/modprobe.d/nixos.conf").unwrap_or_default();

        for &(mod_name, desc) in DANGEROUS_MODULES {
            let loaded = loaded_modules.lines().any(|l| l.starts_with(mod_name));
            let blacklisted = modprobe_conf.contains(&format!("blacklist {}", mod_name));
            if loaded || !blacklisted {
                unblacklisted_modules.push(format!("{}: {}", mod_name, desc));
            }
        }

        let has_unblacklisted = !unblacklisted_modules.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "FORENSIC_MODULE_BLACKLIST".to_string(),
            title: "Dangerous & Legacy Kernel Protocols & FireWire Module Blacklist".to_string(),
            severity: Severity::High,
            status: if !has_unblacklisted { Status::Pass } else { Status::Warn },
            description: if !has_unblacklisted {
                "All legacy network protocols (DCCP, SCTP, RDS, TIPC) and FireWire DMA drivers are blacklisted".to_string()
            } else {
                format!("Detected {} unblacklisted legacy kernel protocol modules (exploit attack surface)", unblacklisted_modules.len())
            },
            items: unblacklisted_modules,
            nixos_fix: if has_unblacklisted {
                Some("boot.blacklistedKernelModules = [\n  \"dccp\" \"sctp\" \"rds\" \"tipc\"\n  \"firewire-core\" \"firewire_ohci\"\n];".to_string())
            } else {
                None
            },
            doc_url: Some("https://wiki.archlinux.org/title/Kernel_module#Blacklisting"),
        });

        // 6. Active Video/Webcam Hardware Capture Probe
        let mut active_webcam_procs = Vec::new();
        if Path::new("/dev/video0").exists() {
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if let Ok(pid) = name.parse::<i32>() {
                        let fd_dir = format!("/proc/{}/fd", pid);
                        if let Ok(fds) = fs::read_dir(fd_dir) {
                            for fd in fds.flatten() {
                                if let Ok(target) = fs::read_link(fd.path()) {
                                    if target.to_string_lossy().starts_with("/dev/video") {
                                        let comm =
                                            fs::read_to_string(format!("/proc/{}/comm", pid))
                                                .unwrap_or_else(|_| "unknown".to_string())
                                                .trim()
                                                .to_string();
                                        active_webcam_procs.push(format!(
                                            "PID {} ({}) -> {}",
                                            pid,
                                            comm,
                                            target.display()
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let webcam_busy = !active_webcam_procs.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "FORENSIC_CAMERA_ACTIVE_PROBE".to_string(),
            title: "Active Webcam & Video Device Capture (/dev/video*)".to_string(),
            severity: Severity::High,
            status: if !webcam_busy { Status::Pass } else { Status::Warn },
            description: if !webcam_busy {
                "No active processes holding open video device descriptors (/dev/video*)".to_string()
            } else {
                format!("Detected {} processes currently streaming or recording from webcam /dev/video*", active_webcam_procs.len())
            },
            items: active_webcam_procs,
            nixos_fix: None,
            doc_url: Some("https://www.kernel.org/doc/html/latest/admin-guide/media/v4l-drivers.html"),
        });

        // 7. Kernel Entropy Pool Quality
        let entropy_str =
            fs::read_to_string("/proc/sys/kernel/random/entropy_avail").unwrap_or_default();
        let entropy_val: u32 = entropy_str.trim().parse().unwrap_or(0);
        let entropy_ok = entropy_val >= 256;

        findings.push(Finding {
            domain: self.domain(),
            check_id: "FORENSIC_KERNEL_ENTROPY".to_string(),
            title: "Cryptographic Kernel Entropy Pool Availability".to_string(),
            severity: Severity::Medium,
            status: if entropy_ok {
                Status::Pass
            } else {
                Status::Warn
            },
            description: format!(
                "Available kernel entropy: {} bits (256 bits represents saturated CSPRNG pool)",
                entropy_val
            ),
            items: Vec::new(),
            nixos_fix: if entropy_ok {
                None
            } else {
                Some("security.rngd.enable = true;".to_string())
            },
            doc_url: Some("https://man7.org/linux/man-pages/man4/random.4.html"),
        });

        findings
    }
}
