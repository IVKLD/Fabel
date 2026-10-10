use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct DataLeaksChecker;

#[async_trait]
impl Checker for DataLeaksChecker {
    fn domain(&self) -> &'static str {
        "Anti-Surveillance, Data Exfiltration & Anti-Forensics"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. RAM Cold Boot & Forensic Memory Wiping (init_on_free=1, init_on_alloc=1)
        let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
        let init_on_alloc = cmdline.contains("init_on_alloc=1");
        let init_on_free = cmdline.contains("init_on_free=1");
        let page_shuffle = cmdline.contains("page_alloc.shuffle=1");
        let slab_nomerge = cmdline.contains("slab_nomerge");

        let mut missing_ram_params = Vec::new();
        if !init_on_alloc {
            missing_ram_params.push("init_on_alloc=1 (zero memory on allocation)".to_string());
        }
        if !init_on_free {
            missing_ram_params.push(
                "init_on_free=1 (zero memory on free to wipe encryption keys & credentials)"
                    .to_string(),
            );
        }
        if !page_shuffle {
            missing_ram_params
                .push("page_alloc.shuffle=1 (page allocator layout randomization)".to_string());
        }
        if !slab_nomerge {
            missing_ram_params
                .push("slab_nomerge (isolate heap allocations against exploitation)".to_string());
        }

        let ram_hardened = missing_ram_params.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "LEAK_RAM_FORENSICS_WIPE".to_string(),
            title: "Kernel RAM Zeroing & Cold Boot Memory Forensic Hardening".to_string(),
            severity: Severity::Critical,
            status: if ram_hardened { Status::Pass } else { Status::Fail },
            description: if ram_hardened {
                "Kernel memory zeroing active: RAM pages sanitized on free to thwart Cold Boot memory acquisition".to_string()
            } else {
                "Kernel does not zero freed RAM pages: master encryption keys, passwords and TLS sessions remain in RAM upon seizure or crash".to_string()
            },
            items: missing_ram_params,
            nixos_fix: if ram_hardened {
                None
            } else {
                Some("boot.kernelParams = [\n  \"init_on_alloc=1\"\n  \"init_on_free=1\"\n  \"page_alloc.shuffle=1\"\n  \"slab_nomerge\"\n];".to_string())
            },
            doc_url: Some("https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html#init-on-alloc"),
        });

        // 2. Hardware MAC Address Randomization (Radio Fingerprinting)
        let nm_conf_path = "/etc/NetworkManager/NetworkManager.conf";
        let mut mac_randomized = false;
        let mut scan_rand = false;
        if Path::new(nm_conf_path).exists() {
            let nm_conf = fs::read_to_string(nm_conf_path).unwrap_or_default();
            scan_rand = nm_conf.contains("wifi.scan-rand-mac-address=true");
            let wifi_rand = nm_conf.contains("wifi.cloned-mac-address=random");
            let eth_rand = nm_conf.contains("ethernet.cloned-mac-address=random");
            mac_randomized = scan_rand && (wifi_rand || eth_rand);
        }

        let mut mac_issues = Vec::new();
        if !scan_rand {
            mac_issues.push("Wi-Fi probe scanning broadcasts real hardware MAC address (wifi.scan-rand-mac-address=false)".to_string());
        }
        if !mac_randomized {
            mac_issues.push("Permanent factory MAC address used on active network interfaces (enables physical location tracking)".to_string());
        }

        findings.push(Finding {
            domain: self.domain(),
            check_id: "LEAK_MAC_RANDOMIZATION".to_string(),
            title: "Wi-Fi & Ethernet Hardware MAC Address Randomization".to_string(),
            severity: Severity::High,
            status: if mac_issues.is_empty() { Status::Pass } else { Status::Fail },
            description: if mac_issues.is_empty() {
                "MAC address randomization active for probe requests and active connections".to_string()
            } else {
                "Static hardware MAC address is broadcast: physical movements and device identity can be tracked across Wi-Fi networks".to_string()
            },
            items: mac_issues,
            nixos_fix: if mac_randomized {
                None
            } else {
                Some("networking.networkmanager.wifi.macAddress = \"random\";\nnetworking.networkmanager.wifi.scanRandMacAddress = true;\nnetworking.networkmanager.ethernet.macAddress = \"random\";".to_string())
            },
            doc_url: Some("https://blogs.gnome.org/thaller/2016/08/26/mac-address-spoofing-in-networkmanager-1-4-0/"),
        });

        // 3. Persistent Unencrypted Clipboard Storage
        let mut clipboard_leaks = Vec::new();
        if let Ok(home) = env::var("HOME") {
            let copyq_tab = format!("{}/.config/copyq/copyq_tab_JmNsaXBib2FyZA==.dat", home);
            let p = Path::new(&copyq_tab);
            if p.exists() {
                if let Ok(meta) = fs::metadata(p) {
                    let mode = meta.permissions().mode() & 0o777;
                    let size = meta.len();
                    if mode & 0o044 != 0 {
                        clipboard_leaks.push(format!(
                            "{}: mode {:o} (world-readable clipboard history: {} bytes)",
                            copyq_tab, mode, size
                        ));
                    } else {
                        clipboard_leaks.push(format!(
                            "{}: unencrypted on-disk clipboard storage active ({} bytes)",
                            copyq_tab, size
                        ));
                    }
                }
            }
        }

        let has_clip_leaks = !clipboard_leaks.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "LEAK_CLIPBOARD_PERSISTENCE".to_string(),
            title: "Unencrypted Clipboard Storage on Disk (CopyQ / Klipper)".to_string(),
            severity: Severity::High,
            status: if !has_clip_leaks { Status::Pass } else { Status::Warn },
            description: if !has_clip_leaks {
                "No unencrypted on-disk clipboard caches detected".to_string()
            } else {
                "Clipboard manager stores full history (including copied passwords, 2FA codes, seed phrases) unencrypted on disk".to_string()
            },
            items: clipboard_leaks,
            nixos_fix: if has_clip_leaks {
                Some("# Configure ephemeral in-memory clipboard or password filtering in CopyQ:\n# chmod 600 ~/.config/copyq/copyq_tab_*.dat".to_string())
            } else {
                None
            },
            doc_url: Some("https://copyq.readthedocs.io/"),
        });

        // 4. Global DO_NOT_TRACK & Developer Telemetry Beacons
        let dnt = env::var("DO_NOT_TRACK").unwrap_or_default() == "1";
        let dotnet_optout = env::var("DOTNET_CLI_TELEMETRY_OPTOUT").unwrap_or_default() == "1";
        let homebrew_optout = env::var("HOMEBREW_NO_ANALYTICS").unwrap_or_default() == "1";

        let mut telemetry_missing = Vec::new();
        if !dnt {
            telemetry_missing
                .push("DO_NOT_TRACK=1 missing (global telemetry opt-out standard)".to_string());
        }
        if !dotnet_optout {
            telemetry_missing.push("DOTNET_CLI_TELEMETRY_OPTOUT=1 missing".to_string());
        }
        if !homebrew_optout {
            telemetry_missing.push("HOMEBREW_NO_ANALYTICS=1 missing".to_string());
        }

        let dnt_clean = telemetry_missing.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "LEAK_GLOBAL_DO_NOT_TRACK".to_string(),
            title: "Global DO_NOT_TRACK & Runtime Telemetry Suppression".to_string(),
            severity: Severity::Low,
            status: if dnt_clean { Status::Pass } else { Status::Warn },
            description: if dnt_clean {
                "Global DO_NOT_TRACK and toolchain telemetry beacons suppressed in environment".to_string()
            } else {
                "Missing environment flags: CLI developer tools and web toolchains phone home telemetry beacons with machine UUIDs".to_string()
            },
            items: telemetry_missing,
            nixos_fix: if dnt_clean {
                None
            } else {
                Some("environment.sessionVariables = {\n  DO_NOT_TRACK = \"1\";\n  DOTNET_CLI_TELEMETRY_OPTOUT = \"1\";\n  HOMEBREW_NO_ANALYTICS = \"1\";\n  NEXT_TELEMETRY_DISABLED = \"1\";\n};".to_string())
            },
            doc_url: Some("https://consoledonottrack.com/"),
        });

        // 5. Dual-Stack IPv6 Proxy Leak Prevention
        let disable_ipv6_val = fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
            .unwrap_or_default()
            .trim()
            .to_string();

        let ipv6_disabled = disable_ipv6_val == "1";
        findings.push(Finding {
            domain: self.domain(),
            check_id: "LEAK_IPV6_PROXY_BYPASS".to_string(),
            title: "Dual-Stack IPv6 Proxy Leak & SORM Bypass Prevention".to_string(),
            severity: Severity::High,
            status: if ipv6_disabled { Status::Pass } else { Status::Warn },
            description: if ipv6_disabled {
                "IPv6 disabled globally: prevents dual-stack DNS and TCP leaks past encrypted IPv4 proxy tunnel".to_string()
            } else {
                "IPv6 is enabled: risk of IPv6 traffic and DNS bypassing proxy directly to ISP/DPI gateways".to_string()
            },
            items: Vec::new(),
            nixos_fix: if ipv6_disabled {
                None
            } else {
                Some("networking.enableIPv6 = false; # Prevent unproxied IPv6 leaks".to_string())
            },
            doc_url: Some("https://datatracker.ietf.org/doc/html/rfc7359"),
        });

        // 6. Shell History Secrets & Credential Leakage
        let mut sensitive_history_hits = Vec::new();
        if let Ok(home) = env::var("HOME") {
            for hist_rel in &[
                ".bash_history",
                ".zsh_history",
                ".local/share/fish/fish_history",
            ] {
                let hist_path = format!("{}/{}", home, hist_rel);
                let p = Path::new(&hist_path);
                if p.exists() {
                    if let Ok(content) = fs::read_to_string(p) {
                        for line in content.lines().take(5000) {
                            let l = line.trim();
                            if l.contains("ghp_")
                                || l.contains("glpat-")
                                || l.contains("AKIA")
                                || l.contains("Bearer ")
                                || l.contains("export AWS_SECRET")
                                || (l.starts_with("curl ") && l.contains(" -u "))
                            {
                                let sanitized = if l.len() > 40 {
                                    format!("{}...", &l[..40])
                                } else {
                                    l.to_string()
                                };
                                sensitive_history_hits
                                    .push(format!("In {}: {}", hist_rel, sanitized));
                                if sensitive_history_hits.len() >= 5 {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        let has_secret_hits = !sensitive_history_hits.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "LEAK_SHELL_HISTORY_TOKENS".to_string(),
            title: "Shell Command History Credentials & API Token Leakage".to_string(),
            severity: Severity::High,
            status: if !has_secret_hits { Status::Pass } else { Status::Fail },
            description: if !has_secret_hits {
                "No cleartext API tokens, cloud keys or passwords detected in queried shell history files".to_string()
            } else {
                format!("Detected {} sensitive credentials (tokens, bearer auth, passwords) logged in shell history", sensitive_history_hits.len())
            },
            items: sensitive_history_hits,
            nixos_fix: if has_secret_hits {
                Some("programs.bash.interactiveShellInit = \"HISTCONTROL=ignoreboth:erasedups\";\n# Sanitize shell history: truncate -s 0 ~/.bash_history ~/.local/share/fish/fish_history".to_string())
            } else {
                None
            },
            doc_url: Some("https://man7.org/linux/man-pages/man1/bash.1.html"),
        });

        findings
    }
}
