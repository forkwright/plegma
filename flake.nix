{
  description = "plegma development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in {
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo
              pkgs.rustc
              pkgs.rust-analyzer
              pkgs.clippy
              pkgs.rustfmt
              pkgs.cargo-nextest
              pkgs.cargo-deny
              pkgs.pkg-config
              pkgs.shellcheck
              pkgs.nixfmt-rfc-style
            ];
          };
        }
      );
    };
}
