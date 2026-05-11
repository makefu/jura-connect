{
  description = "jura-connect — Python WiFi interface for Jura coffee machines";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = pkgs.python313;
        # Build the library itself with a stock setuptools backend.
        package = python.pkgs.buildPythonPackage {
          pname = "jura_wifi";
          version = "0.1.0";
          src = ./.;
          pyproject = true;
          build-system = [ python.pkgs.setuptools ];
          nativeCheckInputs = [ python.pkgs.pytestCheckHook ];
          # Run the tests as the package's check phase. pytestCheckHook picks
          # up tests/ on its own.
          enabledTestPaths = [ "tests" ];
          pytestFlags = [ "-q" ];
          doCheck = true;
          meta = {
            description = "Python WiFi interface for Jura coffee machines (TT237W / S8)";
            mainProgram = "jura-wifi";
          };
        };
        # A separate `checks.tests` derivation that runs pytest as a
        # passthrough build, so `nix flake check` exercises the full suite.
        tests = pkgs.runCommand "jura-wifi-tests"
          {
            nativeBuildInputs = [
              (python.withPackages (ps: [ ps.pytest ]))
            ];
            src = ./.;
          } ''
            cp -R "$src" workdir
            chmod -R u+w workdir
            cd workdir
            export PYTHONPATH=$PWD
            pytest tests/ -q
            touch $out
          '';
      in {
        packages.default = package;
        packages.jura-wifi = package;
        apps.default = flake-utils.lib.mkApp { drv = package; };
        checks.tests = tests;
        checks.default = tests;
        devShells.default = pkgs.mkShell {
          packages = [
            (python.withPackages (ps: [ ps.pytest ]))
          ];
        };
      });
}
