{
  description = "jura-connect — Python WiFi interface for Jura coffee machines";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = pkgs.python313;
        # The package's check phase runs everything CI runs: ruff
        # lint + format, ty type-check, and the pytest suite. Putting
        # them on the package (rather than in separate `checks.*`
        # derivations) means a plain `nix build .#default` exercises
        # the full QA gate.
        package = python.pkgs.buildPythonPackage {
          pname = "jura_connect";
          version = "0.6.0";
          src = ./.;
          pyproject = true;
          build-system = [ python.pkgs.setuptools ];
          # ruff and ty work on the source tree and run before the
          # build (preBuild), so they're build-time tools. pytest
          # exercises the installed package and stays under
          # nativeCheckInputs / pytestCheckHook.
          nativeBuildInputs = [ pkgs.ruff pkgs.ty ];
          nativeCheckInputs = [ python.pkgs.pytestCheckHook ];
          enabledTestPaths = [ "tests" ];
          pytestFlags = [ "-q" ];
          # Lint + type-check the source before it is built. Running
          # at preBuild keeps ty looking only at the source tree (not
          # the post-install site-packages copy, which would create a
          # second copy of the package and confuse module resolution).
          preBuild = ''
            echo "==> ruff check"
            ruff check jura_connect/ tests/
            echo "==> ruff format --check"
            ruff format --check jura_connect/ tests/
            echo "==> ty check jura_connect/"
            ty check jura_connect/
          '';
          doCheck = true;
          meta = {
            description = "Python WiFi interface for Jura coffee machines (TT237W / S8)";
            mainProgram = "jura-connect";
          };
        };
      in {
        packages.default = package;
        packages.jura-connect = package;
        apps.default = flake-utils.lib.mkApp { drv = package; };
        # `nix flake check` builds the package, which itself runs
        # ruff + ty + pytest in its preCheck/checkPhase. One QA gate,
        # one derivation.
        checks.default = package;
        devShells.default = pkgs.mkShell {
          packages = [
            (python.withPackages (ps: [ ps.pytest ]))
            pkgs.ruff
            pkgs.ty
          ];
        };
      });
}
