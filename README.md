# 🛡️ Fabel

[![CI](https://github.com/IVKLD/Fabel/actions/workflows/ci.yml/badge.svg)](https://github.com/IVKLD/Fabel/actions/workflows/ci.yml)
[![Release](https://github.com/IVKLD/Fabel/actions/workflows/release.yml/badge.svg)](https://github.com/IVKLD/Fabel/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![NixOS Flake](https://img.shields.io/badge/NixOS-Flake%20Ready-5277C3?logo=nixos&logoColor=white)](https://nixos.org)

**Fabel** — утилита аудита безопасности и харденинга хоста для NixOS и Linux.

Проверяет 86 параметров системы по 16 категориям (ядро, сеть, утечки данных, права доступа, целостность) и автоматически генерирует готовый файл конфигурации `hardening.nix`, устраняющий найденные уязвимости.

---

## Быстрый запуск

### Без установки (Nix Flakes)
```bash
# Стандартный запуск
nix run github:IVKLD/Fabel

# Передача флагов утилите (через разделитель '--'):
nix run github:IVKLD/Fabel -- --help
nix run github:IVKLD/Fabel -- --all
nix run github:IVKLD/Fabel -- -t
```

Или запуск во временном шелле:
```bash
nix shell github:IVKLD/Fabel -c fabel --help
```

### Сборка из исходников
```bash
cargo build --release
./target/release/fabel
```

---

## Использование

### 1. Быстрый аудит (по умолчанию)
```bash
fabel
```
Запускает сканирование и открывает отчёт в интерактивном пейджере (`less -R`). Выводит только реальные проблемы (2–3 строки на уязвимость) и сводную таблицу в конце. Скролл стрелками / `PageDown`, выход по `q` (экран терминала очищается, история не засоряется).

### 2. Полный аудит со всеми ссылками и деталями
```bash
fabel --all
```
Показывает все 86 проверок (включая пройденные `PASS`), прямые ссылки на документацию ядра/RFC и списки параметров.

### 3. Только ошибки и предупреждения
```bash
fabel -f
```
Показывает только проверки со статусами `FAIL` и `WARN`.

### 4. Только сводная таблица (в один экран)
```bash
fabel -t
```
Выводит только таблицу статусов и баллов по 16 доменам без детализации отдельных проверок.

### 5. Генерация готового фикса для NixOS
```bash
# Записать готовый модуль в файл
fabel -g /etc/nixos/hardening.nix

# Или вывести сгенерированный Nix-код в stdout
fabel -g -
```

### 6. Экспорт в JSON
```bash
fabel -o report.json
```

### 7. Вывод напрямую в stdout (без пейджера)
```bash
fabel --no-pager
```
*(При перенаправлении в файл `fabel > report.txt` пейджер отключается автоматически).*

---

## Применение сгенерированного харденинга в NixOS

1. Сгенерируйте модуль:
   ```bash
   sudo fabel -g /etc/nixos/hardening.nix
   ```
2. Подключите его в `/etc/nixos/configuration.nix`:
   ```nix
   { config, pkgs, ... }:
   {
     imports = [
       ./hardware-configuration.nix
       ./hardening.nix   # <-- сгенерированный профиль
     ];
   }
   ```
3. Примените конфигурацию:
   ```bash
   sudo nixos-rebuild switch
   ```

---

## Что проверяет Fabel (86 проверок / 16 доменов)

| Домен | Что проверяется |
|---|---|
| **Live Internet Leak & Exfiltration** | Реальный внешний IP через DoH, проверка утечки VPN-туннеля, WebRTC STUN leak в браузерах, captive portal перехват, открытые SSH-ключи/токены (.env, .netrc), SMB 445 NTLM leak. |
| **Internet Security & E2E Trust** | Шифрование DNS (DoT/DoH), обход TLS-проверок в переменных окружения, ARP-спуфинг MITM, ICMP redirect hijacking, IPv6 SLAAC tracking, открытые HTTP/FTP сокеты, VPN kill-switch. |
| **Anti-Surveillance & Data Exfiltration** | Очистка ОЗУ при выделении/освобождении (`init_on_free`, `init_on_alloc`), рандомизация Wi-Fi MAC, буфер обмена на диске, отключение телеметрии CLI-утилит (Do Not Track), пароли в истории bash. |
| **Boot & Sysctl Hardening** | KASLR, unprivileged eBPF (`kernel.unprivileged_bpf_disabled`), ptrace Yama scope, SYN cookies, Reverse Path Filtering (`rp_filter`), dmesg restriction, kptr_restrict, SecureBoot. |
| **Digital Forensics Evasion** | Шифрование swap (zram/random disk encryption), сокрытие процессов `/proc` (`hidepid=2`), ротация и ограничение журналов systemd, ephemeral rootfs (`tmpfs` на `/`). |
| **Network & Firewall** | Прослушивание портов на всех интерфейсах (`0.0.0.0` / `::`), политика DROP в файрволе (nftables/iptables), перенаправление пакетов (ip_forward). |
| **DPI & Censorship** | Блокировка QUIC/UDP-443 для предотвращения DPI-блокировок, Encrypted Client Hello (ECH GREASE), отключение TCP timestamps (предотвращение фингерпринтинга аптайма). |
| **PKI & Trust Stores** | Поиск недоверенных корневых сертификатов (включая Russian Trusted Root CA / Минцифры), самоподписанные CA, корпоративные перехватывающие сертификаты. |
| **Physical & Peripherals** | Защита от BadUSB (демон USBGuard), защита от DMA-атак через Thunderbolt/PCIe (IOMMU, bolt), статус контроллера Bluetooth. |
| **Memory Dump Security** | Запрет дампов памяти SUID-процессов (`fs.suid_dumpable = 0`), отключение хранения core dump на диске (`/var/lib/systemd/coredump`). |
| **SSH Hardening** | Запрет входа root (`PermitRootLogin no`), запрет аутентификации по паролю, только Ed25519 хост-ключи, таймауты неактивных сессий. |
| **Privileges & Accounts** | Права `trusted-users` в демоне Nix (предотвращение несанкционированного root через сокет), пустые пароли в shadow, права wheel/sudo. |
| **Hardware & CPU** | Статус аппаратных уязвимостей CPU (Spectre, Meltdown, Retbleed, MDS), обновление микрокода процессора. |
| **Rootkit & Memory Integrity** | Поиск скрытых процессов (невидимых в `/proc`), tainted-статус ядра, анонимная исполняемая память W^X (детект fileless-руткитов). |
| **Stealth & Kernel Subsystems** | Сервис геолокации Geoclue (слив координат по Wi-Fi BSSID), Network Time Security (NTS вместо открытого UDP:123 NTP). |
| **NixOS Declarative Architecture** | Неизменяемость рута (ephemeral root), изоляция сборки пакетов в Nix sandbox. |

---

## Автоматический аудит по расписанию (NixOS Flake)

Для регулярного фонового аудита добавьте модуль `Fabel` в конфигурацию системы:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fabel.url = "github:IVKLD/Fabel";
  };

  outputs = { self, nixpkgs, fabel, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        fabel.nixosModules.default
        {
          services.fabel = {
            enable = true;
            schedule = "daily";                           # Запуск раз в сутки
            reportPath = "/var/log/fabel-report.json";      # Куда сохранять отчёт
            autoGenerateFixPath = "/etc/nixos/hardening.nix"; # Куда писать автофикс
            minScoreAlertThreshold = 80.0;                 # Аварийный статус если балл < 80%
          };
        }
      ];
    };
  };
}
```

---

## Справка по всем флагам CLI

```text
Использование: fabel [ОПЦИИ]

Опции:
  -g, --generate-fix <ФАЙЛ>   Сгенерировать готовый NixOS hardening-модуль (.nix), передайте '-' для вывода в stdout
  -a, --all                   Показать полный отчёт обо всех 86 проверках (включая PASS, ссылки на документацию и параметры)
  -t, --table-only            Вывести только компактную сводную таблицу по 16 доменам
  -f, --failures-only         Показать только проверки с ошибками (FAIL) и предупреждениями (WARN)
  -o, --output <ФАЙЛ.json>    Сохранить полный отчёт в структурированном JSON
  -v, --verbose               Вывести подробные технические описания и списки проверяемых элементов
      --no-pager              Отключить интерактивный пейджер (less) и печатать напрямую в stdout
  -h, --help                  Показать справку
  -V, --version               Показать версию (1.0.0)
```

---

## Лицензия

[MIT](LICENSE) © 2026 [IVKLD](https://github.com/IVKLD)
