use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub struct NetworkFirewallChecker;

impl NetworkFirewallChecker {
    fn parse_listening_ports(path: &str, is_ipv6: bool) -> Vec<u16> {
        let mut ports = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[3] == "0A" {
                    // 0A = TCP_LISTEN
                    if let Some((addr, port_hex)) = parts[1].split_once(':') {
                        let is_wildcard = if is_ipv6 {
                            addr == "00000000000000000000000000000000"
                        } else {
                            addr == "00000000"
                        };

                        if is_wildcard {
                            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                ports.push(port);
                            }
                        }
                    }
                }
            }
        }
        ports
    }
}

#[async_trait]
impl Checker for NetworkFirewallChecker {
    fn domain(&self) -> &'static str {
        "Network Ingress, Firewall & Listening Sockets"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Firewall Active State (nftables or iptables)
        let has_nftables_unit = Path::new("/etc/systemd/system/nftables.service").exists();
        let has_firewall_unit = Path::new("/etc/systemd/system/firewall.service").exists();
        let has_ip_tables = Path::new("/proc/net/ip_tables_names").exists()
            && fs::read_to_string("/proc/net/ip_tables_names")
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);

        let firewall_active = has_nftables_unit || has_firewall_unit || has_ip_tables;

        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_FIREWALL_ACTIVE".to_string(),
            title: "Packet Filtering Firewall Status (nftables/iptables)".to_string(),
            severity: Severity::Critical,
            status: if firewall_active { Status::Pass } else { Status::Fail },
            description: if firewall_active {
                format!(
                    "Firewall active (backend: {})",
                    if has_nftables_unit { "nftables" } else { "iptables" }
                )
            } else {
                "No active firewall rules or services detected! System is exposed directly to LAN/WAN ingress".to_string()
            },
            items: Vec::new(),
            nixos_fix: if firewall_active {
                None
            } else {
                Some("networking.firewall.enable = true;\nnetworking.nftables.enable = true;".to_string())
            },
            doc_url: Some("https://nixos.wiki/wiki/Firewall"),
        });

        // 2. Listening Ingress Sockets (0.0.0.0 / ::)
        let mut open_v4 = Self::parse_listening_ports("/proc/net/tcp", false);
        let mut open_v6 = Self::parse_listening_ports("/proc/net/tcp6", true);
        open_v4.append(&mut open_v6);

        let unique_ports: BTreeSet<u16> = open_v4.into_iter().collect();
        // Ignore standard loopback-only or safe local proxies if not wildcarded
        let mut exposed_descriptions = Vec::new();
        let mut has_high_risk = false;

        for port in &unique_ports {
            let note = match *port {
                21 => {
                    has_high_risk = true;
                    "FTP (unencrypted)"
                }
                23 => {
                    has_high_risk = true;
                    "Telnet (plaintext credentials)"
                }
                2375 => {
                    has_high_risk = true;
                    "Docker API (unauthenticated root daemon)"
                }
                5555 => {
                    has_high_risk = true;
                    "ADB Daemon (Android Debug Bridge)"
                }
                6379 => {
                    has_high_risk = true;
                    "Redis Key-Value Database (unauthenticated by default)"
                }
                27017 => {
                    has_high_risk = true;
                    "MongoDB (NoSQL Database)"
                }
                9200 => {
                    has_high_risk = true;
                    "Elasticsearch Cluster API"
                }
                22 => "SSH Remote Access Server",
                80 => "HTTP Web Server (unencrypted)",
                443 => "HTTPS Web Server",
                _ => "Unidentified wildcard listener",
            };
            exposed_descriptions.push(format!("Port {}/TCP - {}", port, note));
        }

        let exposed_count = unique_ports.len();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "NET_OPEN_INGRESS_SOCKETS".to_string(),
            title: "Wildcard Ingress Sockets (Listening on 0.0.0.0 / ::)".to_string(),
            severity: if has_high_risk { Severity::High } else { Severity::Medium },
            status: if exposed_count == 0 {
                Status::Pass
            } else if has_high_risk {
                Status::Fail
            } else {
                Status::Warn
            },
            description: if exposed_count == 0 {
                "No wildcard listening sockets exposed on external interfaces".to_string()
            } else {
                format!(
                    "Found {} wildcard listening ports bound to all interfaces (0.0.0.0 or ::)",
                    exposed_count
                )
            },
            items: exposed_descriptions,
            nixos_fix: if exposed_count > 0 {
                Some("# Bind services to localhost (127.0.0.1) or restrict allowed ports:\nnetworking.firewall.allowedTCPPorts = [ /* allow only explicit ports */ ];".to_string())
            } else {
                None
            },
            doc_url: Some("https://man7.org/linux/man-pages/man5/proc_net_tcp.5.html"),
        });

        // 3. systemd-resolved Fallback DNS Leak Check
        let resolved_conf = "/etc/systemd/resolved.conf";
        if Path::new(resolved_conf).exists() {
            let content = fs::read_to_string(resolved_conf).unwrap_or_default();
            let mut fallback_active = false;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("FallbackDNS=") {
                    let val = trimmed.trim_start_matches("FallbackDNS=").trim();
                    if !val.is_empty() {
                        fallback_active = true;
                    }
                }
            }

            findings.push(Finding {
                domain: self.domain(),
                check_id: "NET_FALLBACK_DNS_LEAKS".to_string(),
                title: "systemd-resolved Fallback DNS Leak Prevention".to_string(),
                severity: Severity::Medium,
                status: if !fallback_active { Status::Pass } else { Status::Warn },
                description: if !fallback_active {
                    "No plaintext public FallbackDNS resolvers configured in systemd-resolved".to_string()
                } else {
                    "systemd-resolved has FallbackDNS active: may query third-party public resolvers in plaintext upon tunnel disruption".to_string()
                },
                items: Vec::new(),
                nixos_fix: if fallback_active {
                    Some("services.resolved.fallbackDns = [];".to_string())
                } else {
                    None
                },
                doc_url: Some("https://www.freedesktop.org/software/systemd/man/resolved.conf.html"),
            });
        }

        findings
    }
}
