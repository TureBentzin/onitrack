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
        (import ./flake/per-system.nix { inherit projectName; })
      ];

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
    };
}
