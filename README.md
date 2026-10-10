# 🛡️ fabel

[![CI](https://github.com/fabel/fabel/actions/workflows/ci.yml/badge.svg)](https://github.com/fabel/fabel/actions/workflows/ci.yml)
[![Release](https://github.com/fabel/fabel/actions/workflows/release.yml/badge.svg)](https://github.com/fabel/fabel/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![NixOS Flake](https://img.shields.io/badge/NixOS-Flake%20Ready-5277C3?logo=nixos&logoColor=white)](https://nixos.org)
[![Checks](https://img.shields.io/badge/Security%20Checks-78%20Active-brightgreen.svg)](#-audit-domains--checks)

> **Next-generation Host-based Security Audit & Declarative Hardening Engine for NixOS and Linux.**  
> Designed to detect state-actor level surveillance vectors, physical seizure extraction, memory forensics, kernel exploitation, side-channels, and data leaks — with **instant zero-friction generation of declarative NixOS hardening modules**.

---

## ⚡ Quick Start

Run instantly without installing anything using Nix Flakes:

```bash
# Run full system security audit
nix run github:fabel/fabel

# Audit existing NixOS configuration and generate an instant hardening module
sudo nix run github:fabel/fabel -- -f /etc/nixos/configuration.nix -g /etc/nixos/sentinel-hardened.nix
```

Or install in your temporary shell:
```bash
nix-shell -p fabel
```

---

## 🚀 Key Features

- **78 Rigorous Security Checks across 15 Specialized Domains:** Covers physical security, kernel defenses, network fingerprinting, cryptographic trust, anti-forensics, and data leakage.
- **Declarative NixOS Generator (`--generate-fix`):** Synthesizes syntactically valid NixOS modules that resolve detected vulnerabilities with a single import. Unifies `boot.kernelParams`, `boot.blacklistedKernelModules`, and `boot.kernel.sysctl` without collisions.
- **Cold Boot & Memory Forensics Defense:** Checks for DRAM reset attack mitigations (`init_on_alloc`, `init_on_free`, `mem_sleep_default=deep`), swap encryption, and RAM zeroing on shutdown.
- **Anti-Forensics & Activity Scrubbing:** Identifies shell history leakage, swap unencrypted persistence, core dump persistence, systemd crash retention, and ephemeral rootfs setups.
- **Physical & Hardware Protection:** Detects unencrypted `/boot` and ESP Evil Maid attack vectors, DMA attacks via Thunderbolt/PCIe (`iommu=force`), Intel ME / AMD PSP state, and untrusted peripheral auto-authorization (USBGuard).
- **Network Anonymity & Anti-DPI:** Analyzes DNS-over-HTTPS/TLS leaks, TCP timestamp fingerprinting, IPv6 SLAAC address tracking, ICMP redirects, and Tor/WireGuard/SOCKS kill-switch readiness.
- **Internet Security & E2E Anti-Interception:** Detects plaintext DNS leaks, TLS verification bypass flags (`GIT_SSL_NO_VERIFY`, `NODE_TLS_REJECT_UNAUTHORIZED`), local ARP cache poisoning MITM, and unencrypted cleartext sockets (HTTP, FTP, Telnet).
- **Untrusted / State PKI Certificate Scanner:** Inspects system and user trust stores for untrusted Russian state root CAs (*Russian Trusted Root CA*, *Ministry of Digital Development*), enterprise proxy intercepts, and rogue certificate authorities.
- **NixOS Native Flake & Systemd Service:** Deploy as a scheduled background daemon (`services.fabel`) with automatic alerting if your host security score drops.

---

## 📊 Audit Domains & Checks

`fabel` runs **78 automated checks** organized into 15 defensive domains:

| Domain | Description | Key Checks |
|---|---|---|
| **Internet Security & E2E Trust** | End-to-end encryption and traffic interception protection | Plaintext DNS leakage, TLS verification bypass flags, local ARP spoofing MITM, unencrypted sockets, VPN kill-switch |
| **Memory Hardening** | RAM sanitization, cold boot, and heap mitigations | Slab zeroing, page allocation wipe, swap encryption, KASLR, W^X pages, swap file security |
| **Boot Hardening** | Bootloader, EFI, and firmware attack surface | Unencrypted `/boot` (Evil Maid), SecureBoot status, TPM2 PCR enrollment, GRUB password, kernel signature verification |
| **Anti-Forensics** | Traceless execution and persistent residue elimination | Shell history persistence, core dumps to disk, systemd journal wipe on reboot, bash timestamping, auditd logging |
| **Data Leak Prevention** | Covert exfiltration and identity linkage prevention | TCP timestamp tracking, IPv6 privacy extensions (RFC 4941), DNS plaintext leaks, NTP clock drift fingerprinting |
| **Hardware & Peripherals** | Physical access and bus interconnect defenses | Thunderbolt direct DMA attacks, USB Rubber Ducky (USBGuard), FireWire / PCMCIA drivers, camera/mic firmware authorization |
| **Hardware & CPU** | Speculative execution and side-channel mitigations | Spectre, Meltdown, MDS, Foreshadow, Retbleed, SMT/HyperThreading security, Intel ME / AMD PSP state |
| **Stealth & Anonymity** | Active network surveillance and DPI avoidance | TCP window fingerprinting, ICMP redirect reception, mDNS (Avahi) broadcast leaks, NetBIOS/LLMNR broadcasts |
| **Kernel Hardening** | Runtime kernel attack surface minimization | Unprivileged eBPF (`bpf_disabled`), ptrace scoping (`yama`), dmesg restriction, module signature enforcement, TTY line discipline hardening |
| **SUID & File Integrity** | Local privilege escalation vectors | Known GTFOBins SUID binaries (`pkexec`, `sudo`, `mount`, `chsh`), world-writable system executables, `/tmp` sticky bit |
| **Network & Firewall** | Transport layer defenses | Strict SYN Cookies, IP reverse path filtering (rp_filter), packet forwarding, nftables/iptables active drop policy |
| **SSH Hardening** | Remote access cryptographic strength | Root login disabling, password auth prohibition, Ed25519-only host keys, idle timeout enforcement, modern KEX algorithms |
| **PKI & Trust Stores** | Certificate Authority integrity and interception | Russian State CA root inspection, self-signed root proliferation, certificate expiration, untrusted enterprise proxy bundles |
| **Process Sandboxing** | Host defense isolation | Namespaces restriction, AppArmor / Landlock status, user namespaces restrictions, core dumps disabled |

---

## 🛠️ Usage

### Basic CLI Commands

```bash
# Display human-friendly colored terminal report
fabel

# Audit a specific NixOS configuration file
fabel --file /etc/nixos/configuration.nix

# Export machine-readable structured JSON report
fabel --output /tmp/sentinel-report.json

# Generate declarative NixOS hardening module from findings
fabel --generate-fix /etc/nixos/sentinel-hardening.nix
```

### CLI Options

```text
Usage: fabel [OPTIONS]

Options:
  -f, --file <FILE>
          Path to NixOS configuration file to audit (e.g. /etc/nixos/configuration.nix)
  -o, --output <OUTPUT>
          Path to export structured JSON report
  -g, --generate-fix <GENERATE_FIX>
          Path to write automatically generated declarative NixOS hardening module
  -h, --help
          Print help
  -V, --version
          Print version
```

---

## 🛡️ Applying the Generated Hardening Module

When you run `fabel --generate-fix /etc/nixos/sentinel-hardening.nix`, it synthesizes a ready-to-import NixOS module.

Simply import it into your `/etc/nixos/configuration.nix` or Flake:

```nix
# /etc/nixos/configuration.nix
{ config, pkgs, ... }:

{
  imports = [
    ./hardware-configuration.nix
    ./sentinel-hardening.nix  # <-- Import the generated sentinel module
  ];

  # Your normal system configuration...
}
```

Then rebuild your NixOS system:
```bash
sudo nixos-rebuild switch
```

---

## ⚙️ NixOS Module Integration

`fabel` includes a first-class NixOS module for periodic background audits via systemd timers.

### Flake Configuration Example

Add `fabel` to your flake inputs:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fabel.url = "github:fabel/fabel";
  };

  outputs = { self, nixpkgs, fabel, ... }: {
    nixosConfigurations.my-hardened-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        fabel.nixosModules.default
        {
          services.fabel = {
            enable = true;
            schedule = "daily";  # systemd OnCalendar format
            reportPath = "/var/log/fabel-report.json";
            autoGenerateFixPath = "/etc/nixos/sentinel-hardening.nix";
            minScoreAlertThreshold = 85.0; # alert if score drops below 85%
          };
        }
      ];
    };
  };
}
```

---

## 🔒 Security Philosophy & Threat Model

`fabel` is designed around a zero-trust threat model targeting:

1. **State-Level Passive & Active Adversaries:** Deep Packet Inspection (DPI) fingerprinting, forced TLS interception via state-issued root CAs, and network telemetry correlation.
2. **Physical Seizure & Cold Boot Forensics:** Extracting LUKS encryption keys from unpowered RAM chips, exploiting unencrypted `/boot` ESP partitions via Evil Maid firmware rootkits, or direct memory theft over PCIe/Thunderbolt DMA channels.
3. **Local Privilege Escalation & Zero-Days:** Restricting eBPF, clamping `/proc/kallsyms`, disabling legacy ptrace capabilities, and sanitizing SUID binaries against known exploit vectors.

---

## 🧪 Testing & CI

Run the unit and integration test suite:

```bash
# Run Rust tests
nix-shell --run "cargo test"

# Run formatting & Clippy checks
nix-shell --run "cargo fmt -- --check && cargo clippy --all-targets -- -D warnings"

# Check Nix Flake
nix flake check
```

---

## 📜 License

Licensed under the [MIT License](LICENSE).
