{
  description = "nix-sentinel: Host-based Security Audit & Hardening Engine for NixOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages = {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "nix-sentinel";
            version = "0.3.0";
            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.openssl ];

            meta = with pkgs.lib; {
              description = "Next-gen Host Security Audit & Hardening Engine for NixOS";
              homepage = "https://github.com/nix-sentinel/nix-sentinel";
              license = licenses.mit;
              mainProgram = "nix-sentinel";
              platforms = platforms.linux;
            };
          };
        };

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            clippy
            rustfmt
            pkg-config
            openssl
          ];
        };
      }) // {
        nixosModules.default = { config, lib, pkgs, ... }:
          let
            cfg = config.services.nix-sentinel;
          in
          {
            options.services.nix-sentinel = {
              enable = lib.mkEnableOption "nix-sentinel automated security audit daemon";
              schedule = lib.mkOption {
                type = lib.types.str;
                default = "daily";
                description = "systemd calendar event specification for audit runs";
              };
              reportPath = lib.mkOption {
                type = lib.types.path;
                default = "/var/log/nix-sentinel-report.json";
                description = "Location for structured JSON reports";
              };
              autoGenerateFixPath = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = "/etc/nixos/sentinel-hardening.nix";
                description = "Path where declarative hardening configuration will be written";
              };
              minScoreAlertThreshold = lib.mkOption {
                type = lib.types.float;
                default = 80.0;
                description = "Fail systemd service if Security Score drops below this percentage";
              };
            };

            config = lib.mkIf cfg.enable {
              systemd.services.nix-sentinel = {
                description = "nix-sentinel Host Security Audit";
                serviceConfig = {
                  Type = "oneshot";
                  ExecStart = ''
                    ${self.packages.${pkgs.system}.default}/bin/nix-sentinel \
                      --output ${cfg.reportPath} \
                      ${lib.optionalString (cfg.autoGenerateFixPath != null) "--generate-fix ${cfg.autoGenerateFixPath}"}
                  '';
                  ProtectSystem = "strict";
                  ProtectHome = "read-only";
                  ReadOnlyPaths = [ "/" ];
                  ReadWritePaths = [
                    (dirOf cfg.reportPath)
                  ] ++ lib.optional (cfg.autoGenerateFixPath != null) (dirOf cfg.autoGenerateFixPath);
                };
              };

              systemd.timers.nix-sentinel = {
                description = "Run nix-sentinel security audit periodically";
                wantedBy = [ "timers.target" ];
                timerConfig = {
                  OnCalendar = cfg.schedule;
                  Persistent = true;
                };
              };
            };
          };
      };
}
