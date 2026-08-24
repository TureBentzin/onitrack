{
  description = "On I track?";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    let
      projectName = "onitrack";
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
      ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
        }:
        let
          python = pkgs.python3;
          pythonPackages = python.pkgs;

          onitrack = pythonPackages.buildPythonApplication {
            pname = projectName;
            version = "0.1.0";
            pyproject = true;

            src = ./.;

            build-system = with pythonPackages; [
              setuptools
            ];

            nativeCheckInputs = with pythonPackages; [
              pytest
            ];

            pythonImportsCheck = [
              "onitrack"
            ];

            checkPhase = ''
              runHook preCheck
              pytest
              runHook postCheck
            '';
          };
        in
        {
          packages = {
            inherit onitrack;
            default = onitrack;
          };

          apps = {
            onitrack = {
              type = "app";
              program = "${self'.packages.onitrack}/bin/onitrack";
            };
            default = self'.apps.onitrack;
          };

          checks = {
            unit = onitrack;
            lint =
              pkgs.runCommand "${projectName}-lint"
                {
                  nativeBuildInputs = [
                    pythonPackages.ruff
                  ];
                }
                ''
                  ruff check --no-cache ${./.}
                  touch $out
                '';
          };

          formatter = pkgs.nixfmt;

          devShells.default = pkgs.mkShell {
            name = "${projectName}-devshell";

            packages = [
              python
              pythonPackages.pytest
              pythonPackages.ruff
              pythonPackages.mypy
              pythonPackages.build
              pkgs.curl
              pkgs.git
              pkgs.jq
              pkgs.nixfmt
            ];
          };
        };
      flake = {
      };
    };
}
