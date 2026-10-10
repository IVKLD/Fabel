{
  description = "fabel: Host-based Security Audit & Hardening Engine for NixOS";

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
            pname = "fabel";
            version = "1.0.0";
            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.openssl ];

            meta = with pkgs.lib; {
              description = "Next-gen Host Security Audit & Hardening Engine for NixOS";
              homepage = "https://github.com/IVKLD/Fabel";
              license = licenses.mit;
              mainProgram = "fabel";
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
            cfg = config.services.fabel;
          in
          {
            options.services.fabel = {
              enable = lib.mkEnableOption "fabel automated security audit daemon";
              schedule = lib.mkOption {
                type = lib.types.str;
                default = "daily";
                description = "systemd calendar event specification for audit runs";
              };
              reportPath = lib.mkOption {
                type = lib.types.path;
                default = "/var/log/fabel-report.json";
                description = "Location for structured JSON reports";
              };
              autoGenerateFixPath = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = "/etc/nixos/fabel-hardening.nix";
                description = "Path where declarative hardening configuration will be written";
              };
              minScoreAlertThreshold = lib.mkOption {
                type = lib.types.float;
                default = 80.0;
                description = "Fail systemd service if Security Score drops below this percentage";
              };
            };

            config = lib.mkIf cfg.enable {
              systemd.services.fabel = {
                description = "fabel Host Security Audit";
                serviceConfig = {
                  Type = "oneshot";
                  ExecStart = ''
                    ${self.packages.${pkgs.system}.default}/bin/fabel \
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

              systemd.timers.fabel = {
                description = "Run fabel security audit periodically";
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
