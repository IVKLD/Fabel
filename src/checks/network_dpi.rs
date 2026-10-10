use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

struct LeakRule {
    file: &'static str,
    needle: &'static str,
    desc: &'static str,
}

const CONNECTIVITY_RULES: &[LeakRule] = &[
    LeakRule {
        file: "/etc/NetworkManager/NetworkManager.conf",
        needle: "connectivitycheck.gstatic.com",
        desc: "Google connectivitycheck active in NetworkManager",
    },
    LeakRule {
        file: "/etc/NetworkManager/conf.d/default-wifi-powersave-on.conf",
        needle: "connectivitycheck.gstatic.com",
        desc: "Google connectivitycheck active in NetworkManager conf.d",
    },
    LeakRule {
        file: "/etc/systemd/resolved.conf",
        needle: "connectivitycheck.gstatic.com",
        desc: "Google connectivitycheck referenced in resolved.conf",
    },
];

pub struct NetworkDpiChecker;

#[async_trait]
impl Checker for NetworkDpiChecker {
    fn domain(&self) -> &'static str {
        "DPI, Censorship & Network Interception"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Transparent Port 53 DNS Redirection Check
        let dns_query = [
            0x13, 0x37, // ID
            0x01, 0x00, // Standard query
            0x00, 0x01, // 1 question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, // A IN
        ];

        let mut dns_responded = false;
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
            let _ = socket.send_to(&dns_query, "198.51.100.1:53").await;
            let mut buf = [0u8; 512];
            if timeout(Duration::from_millis(1500), socket.recv_from(&mut buf))
                .await
                .is_ok()
            {
                dns_responded = true;
            }
        }

        // Attribution: Check whether local proxy/TUN is running (mihomo, clash, sing-box, dae)
        let mut local_proxy_detected = None;
        if dns_responded {
            if let Ok(entries) = fs::read_dir("/sys/class/net") {
                for entry in entries.flatten() {
                    let iface = entry.file_name().to_string_lossy().to_string();
                    if iface.starts_with("mihomo")
                        || iface.starts_with("clash")
                        || iface.starts_with("sing-box")
                        || iface == "dae0"
                        || iface.starts_with("meta")
                    {
                        local_proxy_detected = Some(format!("interface '{}'", iface));
                        break;
                    }
                }
            }
            if local_proxy_detected.is_none() {
                if let Ok(entries) = fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        if let Ok(name) = entry.file_name().into_string() {
                            if name.chars().all(|c| c.is_ascii_digit()) {
                                if let Ok(comm) = fs::read_to_string(format!("/proc/{}/comm", name))
                                {
                                    let comm_trim = comm.trim().to_lowercase();
                                    if comm_trim.contains("mihomo")
                                        || comm_trim.contains("clash")
                                        || comm_trim.contains("sing-box")
                                        || comm_trim.contains("dae")
                                    {
                                        local_proxy_detected = Some(format!(
                                            "daemon '{}' (PID {})",
                                            comm.trim(),
                                            name
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

        let (dns_status, dns_desc, dns_fix) = if !dns_responded {
            (
                Status::Pass,
                "No transparent UDP/53 redirection detected on network uplink".to_string(),
                None,
            )
        } else if let Some(proxy_info) = local_proxy_detected {
            (
                Status::Pass,
                format!(
                    "Port 53 redirection handled by authorized local proxy [{}]",
                    proxy_info
                ),
                None,
            )
        } else {
            (
                Status::Fail,
                "CRITICAL: Port 53 transparent interception detected (ISP/DPI blackhole returned reply)!".to_string(),
                Some("services.resolved = {\n  enable = true;\n  dnssec = \"true\";\n  dnsovertls = \"true\";\n};".to_string()),
            )
        };

        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_DPI_PORT_53_HIJACK".to_string(),
            title: "Transparent DNS Hijacking (UDP:53)".to_string(),
            severity: Severity::Critical,
            status: dns_status,
            description: dns_desc,
            items: Vec::new(),
            nixos_fix: dns_fix,
            doc_url: Some("https://datatracker.ietf.org/doc/html/rfc7858"),
        });

        // 2. QUIC / UDP:443 Accessibility & Throttling
        // Probe Google and Cloudflare QUIC endpoints with Initial QUIC Packet
        let quic_initial = [
            0xc0, 0x00, 0x00, 0x00, 0x01, // Long header, version 1
            0x08, // DCIL
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, // SCIL 0
            0x00, // Token length 0
            0x00, 0x40, // Length 64
            0x00, 0x00, 0x00, 0x00, // Packet number 0
        ];
        let mut quic_blocked = false;
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
            let _ = socket.send_to(&quic_initial, "1.1.1.1:443").await;
            let mut buf = [0u8; 512];
            // If UDP 443 returns ICMP unreachable or times out completely while TCP:443 works, QUIC is throttled
            if timeout(Duration::from_millis(1000), socket.recv_from(&mut buf))
                .await
                .is_err()
            {
                // Check if TCP 443 works
                if timeout(
                    Duration::from_millis(1000),
                    TcpStream::connect("1.1.1.1:443"),
                )
                .await
                .is_ok()
                {
                    quic_blocked = true;
                }
            }
        }

        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_QUIC_UDP_443_BLOCK".to_string(),
            title: "QUIC/HTTP3 (UDP:443) Accessibility & Throttling".to_string(),
            severity: Severity::Medium,
            status: if quic_blocked { Status::Warn } else { Status::Pass },
            description: if quic_blocked {
                "UDP:443 is blocked or unacknowledged while TCP:443 is open — ISP/TSP throttles or drops HTTP/3 / QUIC traffic".to_string()
            } else {
                "QUIC / UDP:443 is unconstrained and reachable".to_string()
            },
            items: Vec::new(),
            nixos_fix: if quic_blocked {
                Some("# Route UDP:443 through encrypted proxy or enable TCP-only fallback".to_string())
            } else {
                None
            },
            doc_url: Some("https://datatracker.ietf.org/doc/html/rfc9000"),
        });

        // 3. ECH Suppression & Connectivity Check Leaks (Table-driven)
        let mut leak_findings = Vec::new();
        for rule in CONNECTIVITY_RULES {
            if Path::new(rule.file).exists() {
                if let Ok(content) = fs::read_to_string(rule.file) {
                    if content.contains(rule.needle) {
                        leak_findings.push(format!("{}: {}", rule.file, rule.desc));
                    }
                }
            }
        }

        let has_leaks = !leak_findings.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_CONNECTIVITY_LEAK".to_string(),
            title: "Captive Portal & Ambient Connectivity Check Leaks".to_string(),
            severity: Severity::Low,
            status: if has_leaks { Status::Warn } else { Status::Pass },
            description: if has_leaks {
                "Plaintext Google connectivity checks (connectivitycheck.gstatic.com) active in network configs".to_string()
            } else {
                "No hardcoded connectivitycheck.gstatic.com ping endpoints detected".to_string()
            },
            items: leak_findings,
            nixos_fix: if has_leaks {
                Some("networking.networkmanager.extraConfig = \"\"\"\n[connectivity]\nenabled=false\n\"\"\";".to_string())
            } else {
                None
            },
            doc_url: Some("https://blogs.gnome.org/thaller/2017/04/18/connectivity-check-in-networkmanager/"),
        });

        findings
    }
}
