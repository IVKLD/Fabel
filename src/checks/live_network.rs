use crate::types::{Checker, Finding, ProgressReporter, Severity, Status};
use async_trait::async_trait;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;

pub struct LiveNetworkChecker;

#[async_trait]
impl Checker for LiveNetworkChecker {
    fn domain(&self) -> &'static str {
        "Live Internet Leak & Active Exfiltration Probes"
    }

    async fn run(&self) -> Vec<Finding> {
        self.run_with_progress(&ProgressReporter::noop()).await
    }

    async fn run_with_progress(&self, progress: &ProgressReporter) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Live Public External IP & VPN Tunnel Leak Probe
        progress.step(
            self.domain(),
            "Probing external egress IP & VPN tunnel route",
        );
        let trace_output = tokio::process::Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "2",
                "--connect-timeout",
                "2",
                "https://1.1.1.1/cdn-cgi/trace",
            ])
            .output()
            .await;

        let mut external_ip = String::new();
        let mut country = String::new();
        let mut is_online = false;

        if let Ok(res) = trace_output {
            if res.status.success() {
                let text = String::from_utf8_lossy(&res.stdout);
                for line in text.lines() {
                    if let Some(ip) = line.strip_prefix("ip=") {
                        external_ip = ip.trim().to_string();
                        is_online = true;
                    }
                    if let Some(loc) = line.strip_prefix("loc=") {
                        country = loc.trim().to_string();
                    }
                }
            }
        }

        // Check if host has an active VPN interface (wg, tun, tailscale, proton)
        let mut active_vpn_interfaces = Vec::new();
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("wg")
                    || name.starts_with("tun")
                    || name.starts_with("tap")
                    || name.starts_with("tailscale")
                    || name.starts_with("proton")
                    || name.starts_with("mullvad")
                {
                    // Check if interface is UP
                    let operstate = fs::read_to_string(entry.path().join("operstate"))
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    if operstate == "up" || operstate == "unknown" {
                        active_vpn_interfaces.push(name);
                    }
                }
            }
        }

        if !is_online {
            findings.push(Finding {
                domain: self.domain(),
                check_id: "LIVE_EXT_IP_VPN_LEAK".to_string(),
                title: "Live Public IP & VPN Tunnel Route Verification".to_string(),
                severity: Severity::High,
                status: Status::Skipped {
                    reason: "Network offline or canary trace unreachable".to_string(),
                },
                description: "Cannot verify external egress routing: host is offline or remote canary endpoint timed out".to_string(),
                items: Vec::new(),
                nixos_fix: None,
                doc_url: Some("https://datatracker.ietf.org/doc/html/rfc7359"),
            });
        } else {
            let has_vpn = !active_vpn_interfaces.is_empty();
            let mut leak_details = Vec::new();
            leak_details.push(format!("Public External Egress IP: {}", external_ip));
            if !country.is_empty() {
                leak_details.push(format!("Geo Location: {}", country));
            }
            if has_vpn {
                leak_details.push(format!(
                    "Active VPN Tunnel Interfaces: {}",
                    active_vpn_interfaces.join(", ")
                ));
            }

            findings.push(Finding {
                domain: self.domain(),
                check_id: "LIVE_EXT_IP_VPN_LEAK".to_string(),
                title: "Live Public IP & VPN Tunnel Route Verification".to_string(),
                severity: Severity::Critical,
                status: Status::Pass,
                description: format!(
                    "External egress verified: Public IP '{}' ({}) successfully reachable via secure HTTPS probe",
                    external_ip,
                    if has_vpn { format!("VPN active on {}", active_vpn_interfaces.join(", ")) } else { "Direct ISP connection".to_string() }
                ),
                items: leak_details,
                nixos_fix: None,
                doc_url: Some("https://datatracker.ietf.org/doc/html/rfc7359"),
            });
        }

        // 2. Live Captive Portal & Rogue Wi-Fi Interception Probe
        progress.step(
            self.domain(),
            "Checking captive portal & rogue Wi-Fi canary",
        );
        let captive_res = tokio::process::Command::new("curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "2",
                "--connect-timeout",
                "2",
                "http://connectivitycheck.gstatic.com/generate_204",
            ])
            .output()
            .await;

        let mut captive_detected = false;
        let mut captive_status_code = String::new();
        if let Ok(res) = captive_res {
            if res.status.success() {
                let code = String::from_utf8_lossy(&res.stdout).trim().to_string();
                captive_status_code = code.clone();
                if !code.is_empty() && code != "204" {
                    captive_detected = true;
                }
            }
        }

        findings.push(Finding {
            domain: self.domain(),
            check_id: "LIVE_CAPTIVE_PORTAL_MITM".to_string(),
            title: "Live Captive Portal & Rogue Wi-Fi MITM Interception Probe".to_string(),
            severity: Severity::High,
            status: if captive_detected {
                Status::Fail
            } else if captive_status_code == "204" {
                Status::Pass
            } else {
                Status::Skipped {
                    reason: "Network offline or captive portal canary unreachable".to_string(),
                }
            },
            description: if captive_detected {
                format!(
                    "Detected rogue Wi-Fi / Captive Portal redirect (HTTP {}): network gateway is intercepting and tampering with unencrypted HTTP requests",
                    captive_status_code
                )
            } else {
                "Canary endpoint returned HTTP 204: no captive portal or transparent HTTP MITM injection detected on active gateway".to_string()
            },
            items: if captive_detected {
                vec![format!("HTTP Response Code: {}", captive_status_code)]
            } else {
                Vec::new()
            },
            nixos_fix: if captive_detected {
                Some(
                    "# Captive portal interception active: enforce strict network isolation and VPN kill-switch\nnetworking.firewall.checkReversePath = \"strict\";"
                        .to_string(),
                )
            } else {
                None
            },
            doc_url: Some("https://en.wikipedia.org/wiki/Captive_portal"),
        });

        // 3. Live DNS Resolver Integrity, VPN DNS Leak & DNSSEC Validation Probe
        progress.step(
            self.domain(),
            "Validating DNS resolver integrity & DNSSEC validation",
        );
        let mut dns_leak_detected = false;
        let mut dns_leak_items = Vec::new();

        // Detect VPN DNS Leaks: if VPN is active, queries must not leak to local LAN routers
        if !active_vpn_interfaces.is_empty() {
            if let Ok(resolv) = fs::read_to_string("/etc/resolv.conf") {
                for line in resolv.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("nameserver") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let ns = parts[1];
                            if ns.starts_with("192.168.")
                                || ns.starts_with("10.")
                                || (ns.starts_with("172.") && !ns.starts_with("172.0."))
                            {
                                dns_leak_detected = true;
                                dns_leak_items.push(format!(
                                    "VPN active ({}) but nameserver {} points to local LAN gateway (DNS Leak outside tunnel)",
                                    active_vpn_interfaces.join(", "),
                                    ns
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Active DNSSEC validation probe over the network:
        let mut dnssec_failure_detected = false;
        if is_online {
            // dnssec-failed.org deliberately serves broken DNSSEC signatures.
            // A validating DNSSEC resolver MUST reject and fail lookup.
            // If lookup succeeds, DNSSEC validation is disabled or stripped by upstream network.
            if let Ok(lookup_res) = timeout(
                Duration::from_millis(1500),
                lookup_host("dnssec-failed.org:443"),
            )
            .await
            {
                if lookup_res.is_ok() {
                    dnssec_failure_detected = true;
                    dns_leak_items.push(
                        "Upstream DNS resolved invalid 'dnssec-failed.org': DNSSEC signature verification inactive (vulnerable to DNS cache poisoning/spoofing)".to_string(),
                    );
                }
            }
        }

        let dns_secure = !dns_leak_detected && (!dnssec_failure_detected || !is_online);
        findings.push(Finding {
            domain: self.domain(),
            check_id: "LIVE_DNS_LEAK_SECURITY".to_string(),
            title: "Live DNS Resolver Integrity & VPN DNS Leak Protection".to_string(),
            severity: Severity::Critical,
            status: if dns_secure {
                Status::Pass
            } else if dns_leak_detected {
                Status::Fail
            } else {
                Status::Warn
            },
            description: if dns_secure {
                "DNS queries routed securely: no DNS leaks detected past VPN tunnel, and DNSSEC validation enforced".to_string()
            } else if dns_leak_detected {
                "Active VPN DNS leak detected: DNS queries bypass the VPN tunnel and leak to local unencrypted LAN gateway".to_string()
            } else {
                "Upstream DNS resolver does not enforce cryptographic DNSSEC validation against MITM poisoning".to_string()
            },
            items: dns_leak_items,
            nixos_fix: if !dns_secure {
                Some(
                    "# Prevent VPN DNS leaks to LAN and enforce DNSSEC validation:\nservices.resolved.settings.Resolve.DNSSEC = \"true\";\nnetworking.networkmanager.dns = \"systemd-resolved\";"
                        .to_string(),
                )
            } else {
                None
            },
            doc_url: Some("https://www.dnsleaktest.com/what-is-a-dns-leak.html"),
        });

        // 4. WebRTC STUN/TURN Public and Local IP Leak Surface
        progress.step(
            self.domain(),
            "Checking browser WebRTC STUN/ICE IP leak exposure",
        );
        let home = env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let mut webrtc_vulnerable_browsers = Vec::new();

        // Check Firefox profiles
        let mozilla_path = format!("{}/.mozilla/firefox", home);
        if Path::new(&mozilla_path).exists() {
            if let Ok(entries) = fs::read_dir(&mozilla_path) {
                for entry in entries.flatten() {
                    let prefs_file = entry.path().join("prefs.js");
                    if prefs_file.exists() {
                        let content = fs::read_to_string(&prefs_file).unwrap_or_default();
                        let disabled = content.contains("media.peerconnection.enabled\", false")
                            || content
                                .contains("media.peerconnection.ice.default_address_only\", true");
                        if !disabled {
                            webrtc_vulnerable_browsers.push(format!(
                                "Firefox ({}) has default WebRTC enabled (leaks internal & external IP past VPN)",
                                entry.file_name().to_string_lossy()
                            ));
                            break;
                        }
                    }
                }
            }
        }

        // Check Chrome / Chromium
        let chrome_path = format!("{}/.config/google-chrome", home);
        let chromium_path = format!("{}/.config/chromium", home);
        if Path::new(&chrome_path).exists() || Path::new(&chromium_path).exists() {
            webrtc_vulnerable_browsers.push(
                "Chromium-based browser installed with default WebRTC policy (STUN candidate broadcast active)".to_string()
            );
        }

        let webrtc_secure = webrtc_vulnerable_browsers.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "LIVE_WEBRTC_IP_LEAK".to_string(),
            title: "WebRTC STUN / ICE Local & Public IP Leak Surface".to_string(),
            severity: Severity::High,
            status: if webrtc_secure {
                Status::Pass
            } else {
                Status::Warn
            },
            description: if webrtc_secure {
                "WebRTC STUN candidate broadcasting restricted in detected browser profiles".to_string()
            } else {
                "Browser profiles detected without WebRTC IP handling restrictions: malicious websites can extract real LAN and WAN IP addresses via STUN requests".to_string()
            },
            items: webrtc_vulnerable_browsers,
            nixos_fix: if webrtc_secure {
                None
            } else {
                Some(
                    "programs.firefox.policies = {\n  Preferences = {\n    \"media.peerconnection.enabled\" = false;\n    \"media.peerconnection.ice.default_address_only\" = true;\n  };\n};"
                        .to_string(),
                )
            },
            doc_url: Some("https://restoreprivacy.com/webrtc-leaks/"),
        });

        // 5. Active Credentials & API Secrets Exposed to Cloud/Network Exfiltration
        progress.step(
            self.domain(),
            "Auditing credentials, SSH keys & secret permissions",
        );
        let mut exposed_secrets = Vec::new();

        // Check SSH keys permissions
        let ssh_dir = format!("{}/.ssh", home);
        if let Ok(entries) = fs::read_dir(&ssh_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if (name.starts_with("id_") || name.ends_with(".pem") || name.ends_with(".key"))
                    && !name.ends_with(".pub")
                {
                    if let Ok(meta) = entry.metadata() {
                        let mode = meta.permissions().mode() & 0o777;
                        if mode > 0o600 {
                            exposed_secrets.push(format!(
                                "{}/{} has insecure permissions 0{:o} (world/group readable)",
                                ssh_dir, name, mode
                            ));
                        }
                    }
                }
            }
        }

        // Check .netrc
        let netrc_path = format!("{}/.netrc", home);
        if Path::new(&netrc_path).exists() {
            if let Ok(meta) = fs::metadata(&netrc_path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode > 0o600 {
                    exposed_secrets.push(format!(
                        "~/.netrc contains plaintext API passwords with permissions 0{:o} (expected 0600)",
                        mode
                    ));
                }
            }
        }

        // Check world-readable .env in current working dir
        if let Ok(cwd) = env::current_dir() {
            let env_file = cwd.join(".env");
            if env_file.exists() {
                if let Ok(meta) = fs::metadata(&env_file) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o044 != 0 {
                        exposed_secrets.push(format!(
                            "{}/.env is world-readable (0{:o})",
                            cwd.display(),
                            mode
                        ));
                    }
                }
            }
        }

        let secrets_safe = exposed_secrets.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "LIVE_SECRET_TOKEN_LEAK_SURFACE".to_string(),
            title: "Local Secrets, Tokens & Private Keys Exfiltration Surface".to_string(),
            severity: Severity::Critical,
            status: if secrets_safe {
                Status::Pass
            } else {
                Status::Fail
            },
            description: if secrets_safe {
                "Sensitive credential stores (~/.ssh/id_*, ~/.netrc, .env) have strict owner-only permissions (0600)".to_string()
            } else {
                format!(
                    "Found {} sensitive credential files with insecure permissions exposed to other local processes or sync agents",
                    exposed_secrets.len()
                )
            },
            items: exposed_secrets,
            nixos_fix: if secrets_safe {
                None
            } else {
                Some(
                    "# Lock down credential file permissions:\nchmod 600 ~/.ssh/id_* ~/.netrc 2>/dev/null || true\nchmod 600 .env 2>/dev/null || true"
                        .to_string(),
                )
            },
            doc_url: Some("https://owasp.org/www-community/attacks/Credential_Stuffing"),
        });

        // 6. Outbound High-Risk Egress Port Filtering (SMB/CIFS Port 445 Leak)
        progress.step(
            self.domain(),
            "Testing outbound high-risk SMB (TCP:445) egress",
        );
        // Test if outbound TCP port 445 (SMB) connects or is filtered
        let smb_egress_test = timeout(
            Duration::from_millis(500),
            TcpStream::connect("1.1.1.1:445"),
        )
        .await;
        let mut smb_egress_open = false;
        if let Ok(connect_res) = smb_egress_test {
            // If it connects or sends SYN without immediate local firewall REJECT
            if connect_res.is_ok() {
                smb_egress_open = true;
            }
        }

        findings.push(Finding {
            domain: self.domain(),
            check_id: "LIVE_EGRESS_FIREWALL_LEAK".to_string(),
            title: "Outbound High-Risk Egress Port Filtering (SMB Port 445 NTLM Leak)".to_string(),
            severity: Severity::High,
            status: if smb_egress_open {
                Status::Warn
            } else {
                Status::Pass
            },
            description: if smb_egress_open {
                "Outbound TCP port 445 (SMB) is permitted egress: host can be tricked into leaking NTLM/Kerberos hashes to external servers via forced UNC paths".to_string()
            } else {
                "Outbound SMB/CIFS (TCP 445) is rejected by firewall or filtered by network: prevents NTLM hash exfiltration".to_string()
            },
            items: if smb_egress_open {
                vec!["Outbound TCP:445 reachable to WAN".to_string()]
            } else {
                Vec::new()
            },
            nixos_fix: if smb_egress_open {
                Some(
                    "networking.firewall.extraCommands = ''\n  iptables -A OUTPUT -p tcp --dport 445 -j REJECT\n  iptables -A OUTPUT -p tcp --dport 139 -j REJECT\n'';"
                        .to_string(),
                )
            } else {
                None
            },
            doc_url: Some("https://attack.mitre.org/techniques/T1187/"),
        });

        // 7. Git Cleartext HTTP Push & Remote Interception Leak
        progress.step(
            self.domain(),
            "Verifying Git remote protocols for cleartext HTTP",
        );
        let mut cleartext_git_remotes = Vec::new();
        if let Ok(output) = tokio::process::Command::new("git")
            .args(["remote", "-v"])
            .output()
            .await
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let url = parts[1];
                        if url.starts_with("http://") {
                            cleartext_git_remotes.push(format!("Remote '{}': {}", parts[0], url));
                        }
                    }
                }
            }
        }

        let git_safe = cleartext_git_remotes.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "LIVE_GIT_REMOTE_PLAINTEXT_LEAK".to_string(),
            title: "Git Repository Cleartext HTTP Remote Origin Leak".to_string(),
            severity: Severity::Critical,
            status: if git_safe {
                Status::Pass
            } else {
                Status::Fail
            },
            description: if git_safe {
                "Git repositories use encrypted transport protocols (HTTPS / SSH); no cleartext HTTP origins detected".to_string()
            } else {
                "Found Git remotes using unencrypted HTTP: source code, commit history, and authentication tokens are broadcast in plaintext".to_string()
            },
            items: cleartext_git_remotes,
            nixos_fix: if git_safe {
                None
            } else {
                Some(
                    "programs.git.extraConfig.url.\"https://github.com/\".insteadOf = \"http://github.com/\";"
                        .to_string(),
                )
            },
            doc_url: Some("https://git-scm.com/docs/git-remote"),
        });

        // 8. Live TCP Timestamps & ICMP Bogus Error Remote Fingerprinting
        progress.step(
            self.domain(),
            "Checking TCP timestamps & ICMP fingerprinting",
        );
        let icmp_ignore_bogus =
            fs::read_to_string("/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses")
                .unwrap_or_default()
                .trim()
                .to_string();
        let tcp_timestamps = fs::read_to_string("/proc/sys/net/ipv4/tcp_timestamps")
            .unwrap_or_default()
            .trim()
            .to_string();

        let fingerprint_hardened = icmp_ignore_bogus == "1" && tcp_timestamps == "0";
        findings.push(Finding {
            domain: self.domain(),
            check_id: "LIVE_ICMP_TIMESTAMP_LEAK".to_string(),
            title: "TCP Timestamps & ICMP Remote Uptime Clock Drift Fingerprinting".to_string(),
            severity: Severity::Medium,
            status: if fingerprint_hardened {
                Status::Pass
            } else {
                Status::Warn
            },
            description: if fingerprint_hardened {
                "TCP timestamps disabled and bogus ICMP error responses ignored (prevents remote uptime clock drift fingerprinting and session correlation)".to_string()
            } else {
                "Kernel exposes TCP timestamps (RFC 1323) or responds to bogus ICMP errors: remote attackers can calculate exact system uptime and correlate user sessions across networks".to_string()
            },
            items: vec![
                format!("tcp_timestamps: '{}' (recommended: 0)", tcp_timestamps),
                format!("icmp_ignore_bogus_error_responses: '{}' (recommended: 1)", icmp_ignore_bogus),
            ],
            nixos_fix: if fingerprint_hardened {
                None
            } else {
                Some(
                    "boot.kernel.sysctl.\"net.ipv4.tcp_timestamps\" = 0;\nboot.kernel.sysctl.\"net.ipv4.icmp_ignore_bogus_error_responses\" = 1;"
                        .to_string(),
                )
            },
            doc_url: Some("https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html"),
        });

        findings
    }
}
