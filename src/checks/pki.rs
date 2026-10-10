use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use x509_parser::prelude::*;

struct InterceptionSignature {
    pattern: &'static str,
    desc: &'static str,
}

const INTERCEPTION_SIGNATURES: &[InterceptionSignature] = &[
    InterceptionSignature {
        pattern: "Russian Trusted Root CA",
        desc: "Russian State Root CA (Минцифры)",
    },
    InterceptionSignature {
        pattern: "Russian Trusted Sub CA",
        desc: "Russian State Intermediate CA (Минцифры)",
    },
    InterceptionSignature {
        pattern: "Ministry of Digital Development",
        desc: "Минцифры РФ",
    },
    InterceptionSignature {
        pattern: "Минцифры",
        desc: "Минцифры РФ",
    },
    InterceptionSignature {
        pattern: "Минкомсвязь",
        desc: "Минкомсвязь РФ",
    },
    InterceptionSignature {
        pattern: "Госуслуги",
        desc: "Госуслуги CA",
    },
    InterceptionSignature {
        pattern: "AdGuard",
        desc: "AdGuard Local TLS Interception Proxy",
    },
    InterceptionSignature {
        pattern: "Fiddler",
        desc: "Fiddler HTTP Debugger CA",
    },
    InterceptionSignature {
        pattern: "Kaspersky",
        desc: "Kaspersky AV HTTPS Scanner Root",
    },
    InterceptionSignature {
        pattern: "mitmproxy",
        desc: "mitmproxy Interception Root",
    },
    InterceptionSignature {
        pattern: "Charles Proxy",
        desc: "Charles Proxy TLS Inspection",
    },
];

pub struct PkiChecker;

impl PkiChecker {
    fn scan_directory_for_certs(&self, dir: &Path, acc: &mut Vec<PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let p_str = path.to_string_lossy();
                    if !p_str.starts_with("/nix/store")
                        && !p_str.starts_with("/proc")
                        && !p_str.starts_with("/sys")
                    {
                        self.scan_directory_for_certs(&path, acc);
                    }
                } else if path.is_file() {
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if ext == "crt" || ext == "pem" || ext == "der" || ext == "cer" {
                        acc.push(path);
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Checker for PkiChecker {
    fn domain(&self) -> &'static str {
        "PKI, Secondary Trust Stores & Russian CA"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Collect all target certificate store paths
        let mut cert_sources: Vec<PathBuf> = vec![
            PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
            PathBuf::from("/etc/static/ssl/certs/ca-bundle.crt"),
            PathBuf::from("/nix/var/nix/profiles/system/etc/ssl/certs/ca-bundle.crt"),
            PathBuf::from("/nix/var/nix/profiles/default/etc/ssl/certs/ca-bundle.crt"),
        ];

        // System directories
        for sdir in &["/etc/ssl/certs", "/etc/pki/ca-trust", "/etc/pki/tls/certs"] {
            let p = Path::new(sdir);
            if p.exists() {
                self.scan_directory_for_certs(p, &mut cert_sources);
            }
        }

        // Secondary trust stores (NSS DB, Firefox, Chromium profiles, Python certifi)
        if let Ok(home) = std::env::var("HOME") {
            let home_p = PathBuf::from(&home);
            for sub in &[
                ".pki/nssdb",
                ".local/share/ca-certificates",
                ".config/ssl",
                ".local/lib",
                ".mozilla/firefox",
                ".config/chromium",
                ".config/google-chrome",
            ] {
                let target = home_p.join(sub);
                if target.exists() {
                    self.scan_directory_for_certs(&target, &mut cert_sources);
                }
            }
        }

        let mut russian_state_cas = Vec::new();
        let mut generic_mitm_cas = Vec::new();
        let mut scanned_cert_count = 0;
        let mut seen_subjects = HashSet::new();

        for source in &cert_sources {
            if let Ok(raw_data) = fs::read(source) {
                // Parse PEM blocks
                for pem in Pem::iter_from_buffer(&raw_data).flatten() {
                    scanned_cert_count += 1;
                    if let Ok((_, cert)) = parse_x509_certificate(&pem.contents) {
                        let subject = cert.subject().to_string();
                        let issuer = cert.issuer().to_string();
                        let combined = format!("{} | {}", subject, issuer);

                        if seen_subjects.insert(subject.clone()) {
                            for sig in INTERCEPTION_SIGNATURES {
                                if combined.contains(sig.pattern) {
                                    let entry = format!(
                                        "{} [{}] in {}",
                                        subject,
                                        sig.desc,
                                        source.display()
                                    );
                                    if sig.desc.contains("Минцифры") || sig.desc.contains("РФ")
                                    {
                                        russian_state_cas.push(entry);
                                    } else {
                                        generic_mitm_cas.push(entry);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }

                // Parse raw DER certificates
                if let Ok((_, cert)) = parse_x509_certificate(&raw_data) {
                    scanned_cert_count += 1;
                    let subject = cert.subject().to_string();
                    let issuer = cert.issuer().to_string();
                    let combined = format!("{} | {}", subject, issuer);

                    if seen_subjects.insert(subject.clone()) {
                        for sig in INTERCEPTION_SIGNATURES {
                            if combined.contains(sig.pattern) {
                                let entry =
                                    format!("{} [{}] in {}", subject, sig.desc, source.display());
                                if sig.desc.contains("Минцифры") || sig.desc.contains("РФ")
                                {
                                    russian_state_cas.push(entry);
                                } else {
                                    generic_mitm_cas.push(entry);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Russian State CA Finding
        let ru_failed = !russian_state_cas.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "PKI_RUSSIAN_STATE_ROOT_CA".to_string(),
            title: "Russian State Root CA (Минцифры) Interception Risk".to_string(),
            severity: Severity::Critical,
            status: if ru_failed { Status::Fail } else { Status::Pass },
            description: if ru_failed {
                "CRITICAL: Russian State Root CA (Минцифры) detected in trust store! Enables transparent TLS session decryption on state DPI/TSPU gateways".to_string()
            } else {
                format!("Audited {} X.509 certs across system and secondary stores: Russian State Root CA NOT detected", scanned_cert_count)
            },
            items: russian_state_cas,
            nixos_fix: if ru_failed {
                Some("# Strictly isolate trusted certificate bundle in NixOS:\nsecurity.pki.certificates = lib.mkForce [ /* allow only verified Mozilla roots */ ];".to_string())
            } else {
                None
            },
            doc_url: Some("https://www.eff.org/deeplinks/2022/03/russia-creates-its-own-tls-certificate-authority-bypass-sanctions"),
        });

        // Corporate & Inspection Proxy CA Finding
        let mitm_failed = !generic_mitm_cas.is_empty();
        findings.push(Finding {
            domain: self.domain(),
            check_id: "PKI_MITM_PROXY_CA".to_string(),
            title: "Local TLS Inspection & MITM Proxy Certificates".to_string(),
            severity: Severity::High,
            status: if mitm_failed { Status::Fail } else { Status::Pass },
            description: if mitm_failed {
                format!("Detected {} local intercepting root certificates in secondary trust stores", generic_mitm_cas.len())
            } else {
                "No local TLS debugger or AV inspection CAs found in secondary trust stores".to_string()
            },
            items: generic_mitm_cas,
            nixos_fix: if mitm_failed {
                Some("# Ensure declarative trust store purity:\nsecurity.pki.certificates = [ /* explicit trusted only */ ];".to_string())
            } else {
                None
            },
            doc_url: Some("https://en.wikipedia.org/wiki/Man-in-the-middle_attack#Public-key_cryptography"),
        });

        findings
    }
}
