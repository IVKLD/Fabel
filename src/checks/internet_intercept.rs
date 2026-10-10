use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::env;
use std::fs;
use std::path::Path;

pub struct InternetInterceptChecker;

#[async_trait]
impl Checker for InternetInterceptChecker {
    fn domain(&self) -> &'static str {
        "Internet Security, Anti-Interception & E2E Trust"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Plaintext DNS (UDP/TCP:53) Eavesdropping & Interception Leak
        let mut plaintext_dns = false;
        let mut dns_details = String::new();

        if let Ok(resolv) = fs::read_to_string("/etc/resolv.conf") {
            for line in resolv.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let ns = parts[1];
                        // If it points directly to an external IP (not 127.0.0.1 / 127.0.0.53)
                        if ns != "127.0.0.1" && ns != "127.0.0.53" && ns != "::1" {
                            plaintext_dns = true;
                            dns_details = format!(
                                "Direct external nameserver without local DoT/DoH stub: {}",
                                ns
                            );
                            break;
                        }
                    }
                }
            }
        }

        // Also check if systemd-resolved has DNSOverTLS enabled
        let mut dot_active = false;
        if let Ok(resolved_conf) = fs::read_to_string("/etc/systemd/resolved.conf") {
            if resolved_conf.contains("DNSOverTLS=yes") || resolved_conf.contains("DNSOverTLS=true")
            {
                dot_active = true;
            }
        }

        let dns_secure = !plaintext_dns && dot_active;
        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_E2E_DNS_PLAIN_LEAK".to_string(),
            title: "Encrypted DNS (DoT / DoH) & Plaintext Query Leak Prevention".to_string(),
            severity: Severity::Critical,
            status: if dns_secure {
                Status::Pass
            } else if !plaintext_dns {
                Status::Warn
            } else {
                Status::Fail
            },
            description: if dns_secure {
                "DNS queries are encrypted via DNS-over-TLS/DoH (eavesdropping by ISP/DPI thwarted)".to_string()
            } else if !plaintext_dns {
                "Local DNS stub in use, but systemd-resolved DNSOverTLS is not explicitly enforced (DNSOverTLS=yes)".to_string()
            } else {
                format!("Plaintext DNS queries leak to external resolver: {} (ISP and SORM log all visited domains)", dns_details)
            },
            items: if !dns_details.is_empty() { vec![dns_details] } else { Vec::new() },
            nixos_fix: if !dns_secure {
                Some("services.resolved = {\n  enable = true;\n  dnssec = \"true\";\n  dnsovertls = \"true\";\n};\nnetworking.nameservers = [ \"1.1.1.1#cloudflare-dns.com\" \"9.9.9.9#dns.quad9.net\" ];".to_string())
            } else {
                None
            },
            doc_url: Some("https://datatracker.ietf.org/doc/html/rfc7858"),
        });

        // 2. Insecure TLS / SSL Verification Bypass in Environment
        let mut tls_bypass_detected = Vec::new();
        let risky_vars = [
            ("GIT_SSL_NO_VERIFY", "Git certificate verification disabled"),
            (
                "NODE_TLS_REJECT_UNAUTHORIZED",
                "Node.js TLS rejection disabled",
            ),
            ("PYTHONHTTPSVERIFY", "Python HTTPS verification disabled"),
            ("CURL_INSECURE", "Curl insecure flag active"),
            (
                "WGET_NO_CHECK_CERTIFICATE",
                "Wget certificate validation disabled",
            ),
            (
                "PERL_LWP_SSL_VERIFY_HOSTNAME",
                "Perl LWP hostname verification disabled",
            ),
        ];

        for (var, desc) in &risky_vars {
            if let Ok(val) = env::var(var) {
                if val == "1" || val == "0" || val.to_lowercase() == "true" {
                    tls_bypass_detected.push(format!("{}=`{}` ({})", var, val, desc));
                }
            }
        }

        // Also check git global config for http.sslVerify = false
        if let Ok(home) = env::var("HOME") {
            let gitconfig_path = format!("{}/.gitconfig", home);
            if let Ok(gitconfig) = fs::read_to_string(&gitconfig_path) {
                if gitconfig.to_lowercase().contains("sslverify = false") {
                    tls_bypass_detected.push(
                        "~/.gitconfig: http.sslVerify = false (allows MITM code injection)"
                            .to_string(),
                    );
                }
            }
        }

        let tls_secure = tls_bypass_detected.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_E2E_TLS_VERIFY_ENV".to_string(),
            title: "TLS Certificate Verification Bypass & MITM Exposure".to_string(),
            severity: Severity::Critical,
            status: if tls_secure { Status::Pass } else { Status::Fail },
            description: if tls_secure {
                "Strict TLS certificate verification enforced across CLI toolchains, Git and runtime environments".to_string()
            } else {
                format!("Detected {} TLS bypass settings that allow active Man-in-the-Middle certificate forgery without warning", tls_bypass_detected.len())
            },
            items: tls_bypass_detected,
            nixos_fix: if !tls_secure {
                Some("# Remove insecure TLS bypass flags from environment:\n# git config --global http.sslVerify true".to_string())
            } else {
                None
            },
            doc_url: Some("https://cwe.mitre.org/data/definitions/295.html"),
        });

        // 3. Local Network ARP Spoofing & Gateway Poisoning Defenses
        let arp_ignore = fs::read_to_string("/proc/sys/net/ipv4/conf/all/arp_ignore")
            .unwrap_or_default()
            .trim()
            .to_string();
        let arp_announce = fs::read_to_string("/proc/sys/net/ipv4/conf/all/arp_announce")
            .unwrap_or_default()
            .trim()
            .to_string();
        let drop_unicast =
            fs::read_to_string("/proc/sys/net/ipv4/conf/all/drop_unicast_in_l2_multicast")
                .unwrap_or_default()
                .trim()
                .to_string();

        let mut arp_issues = Vec::new();
        if arp_ignore == "0" {
            arp_issues.push("net.ipv4.conf.all.arp_ignore=0 (replies to ARP requests for any local address on any interface)".to_string());
        }
        if arp_announce == "0" {
            arp_issues.push("net.ipv4.conf.all.arp_announce=0 (announces local IP addresses on foreign network interfaces)".to_string());
        }
        if drop_unicast == "0" {
            arp_issues.push("net.ipv4.conf.all.drop_unicast_in_l2_multicast=0 (accepts unicast inside L2 multicast; L2 sniffing vector)".to_string());
        }

        let arp_hardened = arp_issues.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_E2E_ARP_MITM_POISONING".to_string(),
            title: "Local ARP Spoofing, Gateway Poisoning & L2 MITM Protection".to_string(),
            severity: Severity::High,
            status: if arp_hardened { Status::Pass } else { Status::Warn },
            description: if arp_hardened {
                "Kernel ARP resolution hardened against local gateway spoofing and gratuitous ARP MITM attacks".to_string()
            } else {
                "Kernel ARP stack uses lax default settings: vulnerable to local network ARP cache poisoning / gateway hijacking".to_string()
            },
            items: arp_issues,
            nixos_fix: if !arp_hardened {
                Some("boot.kernel.sysctl.\"net.ipv4.conf.all.arp_ignore\" = 1;\nboot.kernel.sysctl.\"net.ipv4.conf.all.arp_announce\" = 2;\nboot.kernel.sysctl.\"net.ipv4.conf.all.drop_unicast_in_l2_multicast\" = 1;\nboot.kernel.sysctl.\"net.ipv4.conf.default.arp_ignore\" = 1;\nboot.kernel.sysctl.\"net.ipv4.conf.default.arp_announce\" = 2;".to_string())
            } else {
                None
            },
            doc_url: Some("https://www.kernel.org/doc/html/latest/admin-guide/sysctl/net.html#arp-ignore"),
        });

        // 4. ICMP Route Redirection Hijack Protection
        let accept_redirects = fs::read_to_string("/proc/sys/net/ipv4/conf/all/accept_redirects")
            .unwrap_or_default()
            .trim()
            .to_string();
        let send_redirects = fs::read_to_string("/proc/sys/net/ipv4/conf/all/send_redirects")
            .unwrap_or_default()
            .trim()
            .to_string();
        let accept_redirects_v6 =
            fs::read_to_string("/proc/sys/net/ipv6/conf/all/accept_redirects")
                .unwrap_or_default()
                .trim()
                .to_string();

        let mut icmp_issues = Vec::new();
        if accept_redirects != "0" {
            icmp_issues.push("net.ipv4.conf.all.accept_redirects=1 (allows rogue routers to hijack and redirect IP traffic)".to_string());
        }
        if send_redirects != "0" {
            icmp_issues.push("net.ipv4.conf.all.send_redirects=1 (host sends ICMP redirects; acts as transit router)".to_string());
        }
        if accept_redirects_v6 != "0" {
            icmp_issues.push(
                "net.ipv6.conf.all.accept_redirects=1 (allows IPv6 route hijacking)".to_string(),
            );
        }

        let icmp_safe = icmp_issues.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_E2E_ICMP_ROUTE_HIJACK".to_string(),
            title: "ICMP Route Redirection Hijacking & Traffic Tampering".to_string(),
            severity: Severity::High,
            status: if icmp_safe { Status::Pass } else { Status::Fail },
            description: if icmp_safe {
                "ICMP packet redirection disabled: untrusted routers cannot silently reroute egress traffic through MITM hops".to_string()
            } else {
                "Host accepts ICMP redirect packets: malicious Wi-Fi nodes can alter local kernel routing table to intercept all connections".to_string()
            },
            items: icmp_issues,
            nixos_fix: if !icmp_safe {
                Some("boot.kernel.sysctl.\"net.ipv4.conf.all.accept_redirects\" = 0;\nboot.kernel.sysctl.\"net.ipv4.conf.default.accept_redirects\" = 0;\nboot.kernel.sysctl.\"net.ipv4.conf.all.send_redirects\" = 0;\nboot.kernel.sysctl.\"net.ipv4.conf.default.send_redirects\" = 0;\nboot.kernel.sysctl.\"net.ipv6.conf.all.accept_redirects\" = 0;\nboot.kernel.sysctl.\"net.ipv6.conf.default.accept_redirects\" = 0;".to_string())
            } else {
                None
            },
            doc_url: Some("https://datatracker.ietf.org/doc/html/rfc792"),
        });

        // 5. IPv6 SLAAC Address Hardware Tracking (RFC 4941 Privacy Extensions)
        let tempaddr = fs::read_to_string("/proc/sys/net/ipv6/conf/all/use_tempaddr")
            .unwrap_or_default()
            .trim()
            .to_string();
        let privacy_ext_active = tempaddr == "2";

        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_E2E_IPV6_SLAAC_TRACKING".to_string(),
            title: "IPv6 SLAAC Hardware MAC Tracking (RFC 4941 Privacy Extensions)".to_string(),
            severity: Severity::High,
            status: if privacy_ext_active { Status::Pass } else { Status::Warn },
            description: if privacy_ext_active {
                "IPv6 Privacy Extensions enabled: rotating temporary pseudorandom addresses prevent global device tracking".to_string()
            } else {
                format!("net.ipv6.conf.all.use_tempaddr is `{}`: IPv6 address may embed static hardware MAC address (EUI-64), enabling persistent user tracking across networks", tempaddr)
            },
            items: if !privacy_ext_active { vec![format!("use_tempaddr = {}", tempaddr)] } else { Vec::new() },
            nixos_fix: if !privacy_ext_active {
                Some("boot.kernel.sysctl.\"net.ipv6.conf.all.use_tempaddr\" = 2;\nboot.kernel.sysctl.\"net.ipv6.conf.default.use_tempaddr\" = 2;".to_string())
            } else {
                None
            },
            doc_url: Some("https://datatracker.ietf.org/doc/html/rfc4941"),
        });

        // 6. Active Cleartext Insecure Sockets (HTTP, FTP, Telnet)
        let mut cleartext_conns = Vec::new();
        if let Ok(tcp_table) = fs::read_to_string("/proc/net/tcp") {
            for line in tcp_table.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let state = parts[3];
                    // State 01 = TCP_ESTABLISHED
                    if state == "01" {
                        let rem_addr = parts[2];
                        if let Some((_, port_hex)) = rem_addr.split_once(':') {
                            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                match port {
                                    80 => cleartext_conns.push(
                                        "Port 80/TCP (Cleartext HTTP transmission)".to_string(),
                                    ),
                                    21 => cleartext_conns.push(
                                        "Port 21/TCP (Cleartext FTP authentication)".to_string(),
                                    ),
                                    23 => cleartext_conns
                                        .push("Port 23/TCP (Cleartext Telnet session)".to_string()),
                                    110 => cleartext_conns
                                        .push("Port 110/TCP (Cleartext POP3 mail)".to_string()),
                                    143 => cleartext_conns
                                        .push("Port 143/TCP (Cleartext IMAP mail)".to_string()),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }

        cleartext_conns.sort();
        cleartext_conns.dedup();
        let cleartext_free = cleartext_conns.is_empty();

        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_E2E_CLEARTEXT_SOCKETS".to_string(),
            title: "Cleartext Protocol Transmissions (HTTP / Telnet / FTP)".to_string(),
            severity: Severity::Medium,
            status: if cleartext_free { Status::Pass } else { Status::Warn },
            description: if cleartext_free {
                "No unencrypted cleartext application sockets (HTTP/80, FTP/21, Telnet/23) currently active".to_string()
            } else {
                format!("Detected {} active connections using legacy unencrypted protocols: payload and credentials visible in plaintext", cleartext_conns.len())
            },
            items: cleartext_conns,
            nixos_fix: if !cleartext_free {
                Some("# Migrate legacy connections to HTTPS, SFTP (SSH), or SSH tunnels".to_string())
            } else {
                None
            },
            doc_url: Some("https://datatracker.ietf.org/doc/html/rfc2818"),
        });

        // 7. LAN Multicast / Broadcast Identity Leaks (mDNS Avahi / LLMNR)
        let mut lan_broadcast_leaks = Vec::new();
        if Path::new("/run/avahi-daemon/pid").exists()
            || Path::new("/var/run/avahi-daemon/pid").exists()
        {
            lan_broadcast_leaks.push("Avahi daemon is running: mDNS (UDP 5353) broadcasts hostname and services to everyone on Wi-Fi/LAN".to_string());
        }

        if let Ok(resolved_conf) = fs::read_to_string("/etc/systemd/resolved.conf") {
            if resolved_conf.contains("LLMNR=yes") {
                lan_broadcast_leaks.push("LLMNR=yes in resolved.conf: responds to unauthenticated LAN name queries (hash capture risk)".to_string());
            }
        }

        let lan_clean = lan_broadcast_leaks.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_E2E_MDNS_LLMNR_LEAK".to_string(),
            title: "LAN Identity Broadcast Leaks (mDNS Avahi / LLMNR Responder)".to_string(),
            severity: Severity::Low,
            status: if lan_clean { Status::Pass } else { Status::Warn },
            description: if lan_clean {
                "Host does not broadcast discovery beacons or respond to unauthenticated LLMNR/mDNS requests".to_string()
            } else {
                "Host broadcasts system identification, hostname and active services to untrusted local Wi-Fi/LAN users".to_string()
            },
            items: lan_broadcast_leaks,
            nixos_fix: if !lan_clean {
                Some("services.avahi.enable = false;\nservices.resolved.llmnr = \"false\";".to_string())
            } else {
                None
            },
            doc_url: Some("https://datatracker.ietf.org/doc/html/rfc6762"),
        });

        // 8. VPN Kill-Switch & Leak Shield Verification
        let mut vpn_tunnel_detected = false;
        let mut tunnel_iface = String::new();
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("wg")
                    || name.starts_with("tun")
                    || name.starts_with("proton")
                    || name.starts_with("mullvad")
                    || name.starts_with("tailscale")
                {
                    vpn_tunnel_detected = true;
                    tunnel_iface = name;
                    break;
                }
            }
        }

        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_E2E_VPN_TUNNEL_STATE".to_string(),
            title: "Encrypted Network Tunnel & VPN Kill-Switch Status".to_string(),
            severity: Severity::Medium,
            status: if vpn_tunnel_detected { Status::Pass } else { Status::Warn },
            description: if vpn_tunnel_detected {
                format!("Encrypted network tunnel interface is active ({}) protecting egress traffic from ISP/carrier interception", tunnel_iface)
            } else {
                "No encrypted tunnel (WireGuard/OpenVPN/Tailscale) active: all internet traffic routes directly through local ISP unshielded".to_string()
            },
            items: if vpn_tunnel_detected { vec![format!("Active interface: {}", tunnel_iface)] } else { Vec::new() },
            nixos_fix: if !vpn_tunnel_detected {
                Some("networking.wireguard.interfaces = {\n  # Configure WireGuard with strict routing to prevent ISP leaks\n};".to_string())
            } else {
                None
            },
            doc_url: Some("https://www.wireguard.com/"),
        });

        findings
    }
}
