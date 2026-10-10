use crate::types::{Checker, Finding, Severity, Status};
use async_trait::async_trait;
use std::fs;
use std::path::Path;

pub struct PeripheralChecker;

#[async_trait]
impl Checker for PeripheralChecker {
    fn domain(&self) -> &'static str {
        "Physical Security, Peripheral & DMA Attack Surface"
    }

    async fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. USBGuard BadUSB Protection
        let has_usbguard_conf = Path::new("/etc/usbguard").exists();
        let has_usbguard_service = Path::new("/etc/systemd/system/usbguard.service").exists()
            || Path::new("/nix/var/nix/profiles/system/bin/usbguard").exists();

        let usbguard_active = has_usbguard_conf || has_usbguard_service;
        findings.push(Finding {
            domain: self.domain(),
            check_id: "PERIPH_USBGUARD_BADUSB".to_string(),
            title: "BadUSB Hardware Protection (USBGuard Daemon)".to_string(),
            severity: Severity::Medium,
            status: if usbguard_active { Status::Pass } else { Status::Warn },
            description: if usbguard_active {
                "USBGuard authorization daemon configured: unauthorized USB devices blocked from registering keystrokes".to_string()
            } else {
                "USBGuard daemon not configured: vulnerable to BadUSB rogue HID keystroke injection upon physical insertion".to_string()
            },
            items: Vec::new(),
            nixos_fix: if usbguard_active {
                None
            } else {
                Some("services.usbguard.enable = true;".to_string())
            },
            doc_url: Some("https://usbguard.github.io/"),
        });

        // 2. Direct Memory Access (DMA) & Thunderbolt Bolt / IOMMU Security
        let tb_present = Path::new("/sys/bus/thunderbolt").exists();
        let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
        let iommu_enabled = cmdline.contains("intel_iommu=on")
            || cmdline.contains("amd_iommu=on")
            || Path::new("/sys/class/iommu").exists();

        let has_bolt = Path::new("/etc/systemd/system/bolt.service").exists();

        if tb_present {
            let secured = has_bolt && iommu_enabled;
            findings.push(Finding {
                domain: self.domain(),
                check_id: "PERIPH_THUNDERBOLT_DMA_BOLT".to_string(),
                title: "Thunderbolt DMA Protection (Bolt Daemon & IOMMU)".to_string(),
                severity: Severity::High,
                status: if secured { Status::Pass } else { Status::Warn },
                description: if secured {
                    "Thunderbolt hardware protected via Bolt enrollment daemon and active IOMMU".to_string()
                } else {
                    "Thunderbolt controller present without Bolt daemon or IOMMU isolation: exposed to DMA memory dumping attacks".to_string()
                },
                items: Vec::new(),
                nixos_fix: if secured {
                    None
                } else {
                    Some("services.hardware.bolt.enable = true;\nboot.kernelParams = [ \"intel_iommu=on\" \"amd_iommu=on\" ];".to_string())
                },
                doc_url: Some("https://man7.org/linux/man-pages/man1/boltctl.1.html"),
            });
        } else {
            findings.push(Finding {
                domain: self.domain(),
                check_id: "PERIPH_THUNDERBOLT_DMA_BOLT".to_string(),
                title: "IOMMU Direct Memory Access (DMA) Protection".to_string(),
                severity: Severity::Medium,
                status: if iommu_enabled { Status::Pass } else { Status::Warn },
                description: if iommu_enabled {
                    "IOMMU DMA memory isolation active in kernel".to_string()
                } else {
                    "IOMMU not explicitly enabled in boot params (intel_iommu=on / amd_iommu=on missing)".to_string()
                },
                items: Vec::new(),
                nixos_fix: if iommu_enabled {
                    None
                } else {
                    Some("boot.kernelParams = [ \"intel_iommu=on\" \"amd_iommu=on\" ];".to_string())
                },
                doc_url: Some("https://www.kernel.org/doc/html/latest/x86/iommu.html"),
            });
        }

        // 3. Bluetooth Attack Surface Audit
        let bt_active = Path::new("/sys/class/bluetooth").exists()
            && fs::read_dir("/sys/class/bluetooth")
                .map(|mut e| e.next().is_some())
                .unwrap_or(false);

        findings.push(Finding {
            domain: self.domain(),
            check_id: "PERIPH_BLUETOOTH_EXPOSURE".to_string(),
            title: "Bluetooth Controller Exposure".to_string(),
            severity: Severity::Low,
            status: if bt_active { Status::Warn } else { Status::Pass },
            description: if bt_active {
                "Bluetooth radio controller is active: potential wireless discovery, BlueBorne and pairing eavesdropping surface".to_string()
            } else {
                "Bluetooth interface disabled or no active radio controllers found".to_string()
            },
            items: Vec::new(),
            nixos_fix: if bt_active {
                Some("# If Bluetooth is not required on this host:\nhardware.bluetooth.enable = false;".to_string())
            } else {
                None
            },
            doc_url: Some("https://man7.org/linux/man-pages/man8/rfkill.8.html"),
        });

        findings
    }
}
