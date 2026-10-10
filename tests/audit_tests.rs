#[cfg(test)]
mod tests {
    use nix_sentinel::checks::anti_forensics::AntiForensicsChecker;
    use nix_sentinel::checks::boot_hardening::BootHardeningChecker;
    use nix_sentinel::checks::core_dumps::CoreDumpsChecker;
    use nix_sentinel::checks::data_leaks::DataLeaksChecker;
    use nix_sentinel::checks::hardware_cpu::HardwareCpuChecker;
    use nix_sentinel::checks::network_firewall::NetworkFirewallChecker;
    use nix_sentinel::checks::peripheral::PeripheralChecker;
    use nix_sentinel::checks::pki::PkiChecker;
    use nix_sentinel::checks::ssh::SshChecker;
    use nix_sentinel::checks::stealth::StealthChecker;
    use nix_sentinel::engine::AuditEngine;
    use nix_sentinel::fix_generator::NixFixGenerator;
    use nix_sentinel::types::{Checker, Finding, Severity, Status};

    #[tokio::test]
    async fn test_boot_hardening_runs() {
        let checker = BootHardeningChecker;
        let findings = checker.run().await;
        assert!(
            !findings.is_empty(),
            "BootHardeningChecker should return findings"
        );
        for f in &findings {
            assert!(!f.check_id.is_empty());
            assert!(!f.title.is_empty());
        }
    }

    #[tokio::test]
    async fn test_hardware_cpu_checker_runs() {
        let checker = HardwareCpuChecker;
        let findings = checker.run().await;
        assert!(
            !findings.is_empty(),
            "HardwareCpuChecker should return findings"
        );
    }

    #[tokio::test]
    async fn test_peripheral_checker_runs() {
        let checker = PeripheralChecker;
        let findings = checker.run().await;
        assert!(
            !findings.is_empty(),
            "PeripheralChecker should return findings"
        );
    }

    #[tokio::test]
    async fn test_network_firewall_checker_runs() {
        let checker = NetworkFirewallChecker;
        let findings = checker.run().await;
        assert!(
            !findings.is_empty(),
            "NetworkFirewallChecker should return findings"
        );
    }

    #[tokio::test]
    async fn test_core_dumps_checker_runs() {
        let checker = CoreDumpsChecker;
        let findings = checker.run().await;
        assert!(
            !findings.is_empty(),
            "CoreDumpsChecker should return findings"
        );
    }

    #[tokio::test]
    async fn test_ssh_checker_runs() {
        let checker = SshChecker;
        let findings = checker.run().await;
        assert!(!findings.is_empty(), "SshChecker should return findings");
    }

    #[tokio::test]
    async fn test_data_leaks_checker_runs() {
        let checker = DataLeaksChecker;
        let findings = checker.run().await;
        assert!(
            !findings.is_empty(),
            "DataLeaksChecker should return findings"
        );
    }

    #[tokio::test]
    async fn test_anti_forensics_checker_runs() {
        let checker = AntiForensicsChecker;
        let findings = checker.run().await;
        assert!(
            !findings.is_empty(),
            "AntiForensicsChecker should return findings"
        );
    }

    #[tokio::test]
    async fn test_pki_checker_runs() {
        let checker = PkiChecker;
        let findings = checker.run().await;
        assert!(!findings.is_empty(), "PkiChecker should return findings");
    }

    #[tokio::test]
    async fn test_stealth_checker_runs() {
        let checker = StealthChecker;
        let findings = checker.run().await;
        assert!(
            !findings.is_empty(),
            "StealthChecker should return findings"
        );
    }

    #[tokio::test]
    async fn test_internet_intercept_checker_runs() {
        let checker = nix_sentinel::checks::internet_intercept::InternetInterceptChecker;
        let findings = checker.run().await;
        assert!(
            !findings.is_empty(),
            "InternetInterceptChecker should return findings"
        );
        for f in &findings {
            assert!(!f.check_id.is_empty());
        }
    }

    #[tokio::test]
    async fn test_audit_engine_scoring_with_warns() {
        let mut engine = AuditEngine::new();
        engine.register(StealthChecker);
        let report = engine.execute().await;
        assert!(report.security_score >= 0.0 && report.security_score <= 100.0);
        assert_eq!(
            report.passed + report.warned + report.failed + report.skipped,
            report.findings.len()
        );
    }

    #[test]
    fn test_nix_fix_generator_outputs_valid_syntax() {
        let sample_findings = vec![
            Finding {
                domain: "Test Domain",
                check_id: "SYSCTL_TEST".to_string(),
                title: "Test Sysctl".to_string(),
                severity: Severity::High,
                status: Status::Fail,
                description: "Failed rule".to_string(),
                items: Vec::new(),
                nixos_fix: Some("boot.kernel.sysctl.\"kernel.randomize_va_space\" = 2;".to_string()),
                doc_url: Some("https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#randomize-va-space"),
            },
            Finding {
                domain: "Test Domain",
                check_id: "SUDO_TEST".to_string(),
                title: "Sudo Check".to_string(),
                severity: Severity::Critical,
                status: Status::Fail,
                description: "Failed rule".to_string(),
                items: Vec::new(),
                nixos_fix: Some("security.sudo.wheelNeedsPassword = true;".to_string()),
                doc_url: Some("https://man7.org/linux/man-pages/man5/sudoers.5.html"),
            },
            Finding {
                domain: "Test Domain",
                check_id: "PASS_TEST".to_string(),
                title: "Passing Check".to_string(),
                severity: Severity::Low,
                status: Status::Pass,
                description: "Passed rule".to_string(),
                items: Vec::new(),
                nixos_fix: Some("should.not.be.included = true;".to_string()),
                doc_url: None,
            },
        ];

        let module = NixFixGenerator::generate_nixos_module(&sample_findings);
        assert!(module.contains("{ config, pkgs, lib, ... }:"));
        assert!(module.contains("\"kernel.randomize_va_space\" = 2;"));
        assert!(module.contains("security.sudo.wheelNeedsPassword = true;"));
        assert!(!module.contains("should.not.be.included"));
    }
}
