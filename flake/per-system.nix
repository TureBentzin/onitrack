{ projectName }:

{
  perSystem =
    { self', pkgs, ... }:
    let
      packaged = import ./packages.nix {
        inherit pkgs projectName;
      };
    in
    {
      packages = {
        inherit (packaged) onitrack;
        default = packaged.onitrack;
      };

      apps = {
        onitrack = {
          type = "app";
          program = "${self'.packages.onitrack}/bin/onitrack";
        };
        default = self'.apps.onitrack;
      };

      checks = {
        unit = packaged.onitrack;
        lint =
          pkgs.runCommand "${projectName}-lint"
            {
              nativeBuildInputs = [
                packaged.pythonPackages.ruff
              ];
            }
            ''
              ruff check --no-cache ${../.}
              touch $out
            '';
      };

      formatter = pkgs.nixfmt;

      devShells.default = pkgs.mkShell {
        name = "${projectName}-devshell";

        packages = [
          packaged.python
          packaged.pythonPackages.pytest
          packaged.pythonPackages.ruff
          packaged.pythonPackages.mypy
          packaged.pythonPackages.build
          pkgs.curl
          pkgs.git
          pkgs.jq
          pkgs.nixfmt
        ];
      };
    };
}
