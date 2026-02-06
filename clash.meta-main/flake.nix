{
  description = "Clash.Meta Config Dev Environment - Reproducible & Hermetic";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          # The packages available in the environment
          buildInputs = with pkgs; [
            lefthook
            mihomo
            uv
            yamllint
            python3
          ];

          # Shell hook to automatically install git hooks on entering the shell
          shellHook = ''
            echo "🛠️  Loading reproducible dev environment..."
            if [ -d .git ]; then
              lefthook install > /dev/null 2>&1
            fi
          '';
        };
      }
    );
}
