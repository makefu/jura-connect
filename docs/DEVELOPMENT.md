# Development

For contributors to `jura_connect` itself. User-facing docs:
[README](../README.md), command catalogue [COMMANDS.md](COMMANDS.md),
destructive gate [DESTRUCTIVE.md](DESTRUCTIVE.md), verification status
[VERIFICATION.md](VERIFICATION.md), protocol reference
[PROTOCOL.md](PROTOCOL.md).

Conventions and guardrails for AI and human contributors are in
[../AGENTS.md](../AGENTS.md).

## Tests, lint, and type-check

The package's build derivation runs **all three** as a single QA gate:

```sh
# Builds the package; preBuild runs ruff + ty, then pytest runs in
# the install-check phase. One command, no separate invocations.
nix build .#default --print-build-logs

# Same derivation, called as a "flake check" — identical behaviour.
nix flake check
```

Concretely the gate is:

1. `ruff check jura_connect/ tests/` — lint.
2. `ruff format --check jura_connect/ tests/` — formatting drift.
3. `ty check jura_connect/` — Astral's type checker on the library.
4. `pytest tests/ -q` — the 805-case test suite against the in-tree
   simulator, including 89-XML profile-registry coverage and the frames
   captured from a real machine in [`captures/`](captures/).

If you want to run any one of them ad-hoc without the whole build,
enter the dev shell (`nix develop`) which has all four tools on
`$PATH`, then run them directly. The [GitHub Actions workflow](../.github/workflows/ci.yml)
runs `nix build .#default` on every push and PR, so the badge at the
top of the README turns green only when all four steps pass.

The test-suite covers:

* every byte value of the cipher key (`test_crypto.py`),
* discovery-reply parsing including the unusual MSB-counted bit checks
  (`test_discovery.py`),
* every handshake state via the simulator + a tiny one-shot socket
  server for the garbage-reply path (`test_handshake.py`),
* every read command and the simulator's destructive-command guardrail
  (`test_reads.py`),
* the JSON credential round-trip plus a full pair→persist→reconnect
  workflow (`test_credentials.py`),
* every entry of the named-command registry round-tripped through the
  simulator, plus error paths and both destructive gates
  (`test_commands.py`),
* the 89-XML profile registry — every bundled machine parses cleanly,
  EF1091 surfaces its S8 EB-specific product codes, alert severities
  follow the XML's `ALERT.Type` attribute (`test_profile.py`),
* `@TV:` progress decoding across all 87 states, unknown codes and
  truncated frames (`test_progress.py`),
* the maintenance-process state machine end to end, including the
  accept commands every bundled XML declares (`test_process.py`),
* the counter banks past `@TR:32`, the batch settings read and its
  per-setting fallback, PMode writes, preselections, the coffee timer,
  the language download and the firmware family (`test_counter_banks.py`,
  `test_settings_bank.py`, `test_pmode.py`, `test_preselections.py`,
  `test_coffee_timer.py`, `test_language_download.py`,
  `test_firmware.py`),
* CLI smoke tests for `command --list`, `command info` against the
  simulator, the `machine-types` / `set-machine-type` subcommands,
  and credential-store interactions (`test_cli.py`).

Note what this does **not** prove. The simulator was written from the
same APK reading as the client, so for everything in the
simulator-verified table of [VERIFICATION.md](VERIFICATION.md) the
tests confirm internal consistency, not correctness against a real
Jura.

## Versioning

This project follows [Semantic Versioning](https://semver.org/). See
[`CHANGELOG.md`](../CHANGELOG.md) for the release history; the current
version is also exposed as `jura_connect.__version__` and
`jura-connect --version`.

## Releasing

Cutting a release is a CLI flow — no clicking around the GitHub UI:

```sh
# 1. Bump the version in the three places it lives, and add a
#    CHANGELOG entry. ./jura_connect/__init__.py, pyproject.toml,
#    flake.nix.
$EDITOR jura_connect/__init__.py pyproject.toml flake.nix CHANGELOG.md

# 2. Verify locally — this is the same gate CI runs.
nix build .#default --print-build-logs

# 3. Commit and push.
git add -A
git commit -m "jura-connect: release vX.Y.Z"
git push

# 4. Tag and push the tag.
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z

# 5. Create the GitHub release. Use --notes-file to feed the
#    matching CHANGELOG section straight in.
awk '/^## \[X\.Y\.Z\]/,/^## \[/{ if (/^## \[/ && !/X\.Y\.Z/) exit; print }' \
    CHANGELOG.md > /tmp/notes.md
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file /tmp/notes.md
```

Publishing the GitHub release triggers the
[`publish` workflow](../.github/workflows/publish.yml), which:

1. re-runs `nix build .#default` against the tag (so a stale or
   broken tag cannot ship);
2. builds the sdist + wheel with `python -m build`;
3. uploads to PyPI via [trusted publishing](https://docs.pypi.org/trusted-publishers/)
   (OIDC — no long-lived API token in repo secrets).

### One-time PyPI setup

Before the first PyPI upload succeeds, register this repo as a
trusted publisher at
<https://pypi.org/manage/account/publishing/> with:

| Field            | Value                              |
| ---------------- | ---------------------------------- |
| PyPI Project name | `jura_connect`                    |
| Owner            | `makefu`                           |
| Repository name  | `jura-connect`                     |
| Workflow name    | `publish.yml`                      |
| Environment name | `pypi`                             |

After registering, create a GitHub environment called `pypi` on the
repo (Settings → Environments → New environment) to match the
workflow's `environment.name`.

### Manual fallback (no CI)

If GitHub Actions is unavailable, the same artefacts can be built
and uploaded by hand. Use `python -m build` (the pypa standard) plus
twine — works on any Python 3.11+:

```sh
python -m pip install --upgrade build twine
python -m build --sdist --wheel --outdir dist/
twine check dist/*
twine upload dist/*    # prompts for credentials
```

Or as a one-shot `nix-shell` if you'd rather not touch the system
Python:

```sh
nix-shell -p 'python313.withPackages(ps: [ ps.build ])' \
          -p python313Packages.twine \
          --run '
    python -m build --sdist --wheel --outdir dist/
    twine check dist/*
    twine upload dist/*
  '
```
