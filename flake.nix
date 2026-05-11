{
  description = "jura-connect — Python WiFi interface for Jura coffee machines";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = pkgs.python313;
        # The package's check phase runs ruff (lint + format) and the
        # pytest suite. ty lives in a separate `checks.ty` derivation
        # (below) because buildPythonPackage populates PYTHONPATH with
        # site-packages dirs that mask the source tree, breaking
        # relative-import resolution inside the package — running ty
        # standalone, outside that env, sidesteps the issue.
        package = python.pkgs.buildPythonPackage {
          pname = "jura_connect";
          version = "0.9.2";
          src = ./.;
          pyproject = true;
          build-system = [ python.pkgs.setuptools ];
          nativeBuildInputs = [ pkgs.ruff ];
          nativeCheckInputs = [ python.pkgs.pytestCheckHook ];
          enabledTestPaths = [ "tests" ];
          pytestFlags = [ "-q" ];
          preBuild = ''
            echo "==> ruff check"
            ruff check jura_connect/ tests/
            echo "==> ruff format --check"
            ruff format --check jura_connect/ tests/
          '';
          doCheck = true;
          meta = {
            description = "Python WiFi interface for Jura coffee machines (TT237W / S8)";
            mainProgram = "jura-connect";
          };
        };
        # ty (Astral's type checker) on the library. Runs outside the
        # buildPythonPackage env so its PYTHONPATH manipulation doesn't
        # mask the source tree.
        tyCheck = pkgs.runCommand "jura-connect-ty"
          {
            nativeBuildInputs = [ pkgs.ty ];
            src = ./.;
          } ''
            cp -R "$src" workdir
            chmod -R u+w workdir
            cd workdir
            ty check jura_connect/
            touch $out
          '';
      in {
        packages.default = package;
        packages.jura-connect = package;
        apps.default = flake-utils.lib.mkApp { drv = package; };
        # `nix flake check` builds the package (ruff + pytest) AND the
        # standalone ty derivation. Together they exercise the full
        # QA gate that CI runs.
        checks.default = package;
        checks.ty = tyCheck;
        devShells.default = pkgs.mkShell {
          packages = [
            (python.withPackages (ps: [ ps.pytest ]))
            pkgs.ruff
            pkgs.ty
          ];
        };
      });
}
