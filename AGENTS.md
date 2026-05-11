# AGENTS.md

Instructions for AI assistants and human contributors working on
`jura-connect`. Distilled from the development history (initial
reverse-engineering, the destructive-command incident, the
`connect`→`command` rewrite, ty cleanup, CI bring-up). Read this
before touching code.

## 1. The protocol is a reverse-engineered hostile target

The Jura WiFi protocol is undocumented and not stable across firmware
families. Every byte value, command code, and bit position in this
repo was derived from one of:

* the J.O.E. Android APK in `apk/ch.toptronic.joe.apk` (decompiled
  with jadx),
* the Jutta-Proto C++ implementations in `protocol-bt-cpp/` /
  `protocol-cpp/` (Bluetooth + UART flavours of the same control
  language),
* live probing of an S8 EB running TT237W V06.11 nicknamed
  "Kaffeebert".

[`docs/PROTOCOL.md`](docs/PROTOCOL.md) is the **source of truth**.
When code reality differs from the doc, fix the doc — don't paper
over the code. Numbers there are observed, not guessed; if a
behaviour surprises you, suspect a firmware difference first.

## 2. Destructive commands can physically damage the machine

These prefixes change the machine's state — start cleaning cycles
(consumes a tablet, locks the machine for 5+ min, no remote abort),
descale, brew product, overwrite WiFi/PIN settings (wrong values =
factory reset on the machine itself to recover), reset maintenance
counters (irreversible):

```
@TG:21 @TG:23 @TG:24 @TG:25 @TG:26 @TG:7E @TG:FF
@TF:02 @AN:02 @TP: @HW:
```

Hard rules:

* **Never invoke a destructive prefix during development "to see what
  happens".** The first version of this project shipped after an
  accidental `@TG:7E` reset the counters on a real machine. The
  guardrails below exist because of that incident.
* **`jura_connect.commands.DESTRUCTIVE_PREFIXES` is the canonical
  list.** The simulator, the runtime gate, and the `raw` payload
  inspector all read from it. Add new prefixes there, never inline
  them.
* **The simulator refuses destructive prefixes with `@an:error` by
  default** — this is a deliberate test-suite guardrail. A test
  that needs to exercise the wire-level path for a destructive
  command must pass `allow_destructive=True` and assert against
  `@an:error`, not stub the simulator around it.
* **`run_named(..., allow_destructive=False)` is the default.** The
  CLI exposes the same gate as `--allow-destructive-commands`.
  Library callers that bypass it must do so explicitly.

When adding a new destructive command:

1. Mark `CommandSpec(destructive=True, danger="...")` with a danger
   string that explains *what* the command does on the machine AND
   *how to recover* if it bites (supplies consumed, factory reset,
   irreversible — be specific).
2. Add it to the parametrised `_DESTRUCTIVE_INVOCATIONS` list in
   `tests/test_commands.py` so both gating paths get tested.

## 3. Tests use a real simulator, not mocks

The `jura_connect.simulator` module is a real TCP server speaking
the same wire protocol as the dongle. It imports the *same*
`crypto.py` and `protocol.py` the client uses, so any
encoding/decoding regression breaks both halves of the suite at once.

Don't add `unittest.mock` or monkey-patches. If a behaviour can't be
expressed in the simulator (rare), either extend the simulator
itself, or write a tiny one-shot socket server inline in the test
(see `test_handshake.py::test_handshake_error_on_garbage_reply`).

## 4. Library does the work; CLI is a thin shell

* Structured data and its presentation live together. Every result
  dataclass exposes `format()` (human pretty-print) and `to_dict()`
  (JSON-serialisable). The CLI calls these and prints — it never
  composes the output itself.
* The named-command registry (`jura_connect.commands`) is the single
  source of truth for what commands exist. The CLI and library
  consumers both go through `run_named(client, name, args)`.
* New CLI flags that imply business logic belong in the library
  first: add the kwarg to `run_named` and the data type's `to_dict`,
  then wire the flag in `__main__.py`.

## 5. `nix build .#default` is the single QA gate

The package's build derivation runs lint + type-check + tests as one
pipeline:

1. `ruff check jura_connect/ tests/`
2. `ruff format --check jura_connect/ tests/`
3. `ty check jura_connect/` (Astral's type checker; library only —
   `tests/` is excluded because it imports pytest)
4. `pytest tests/ -q`

Run `nix build .#default --print-build-logs` before every commit.
CI runs exactly the same command on every push and PR. The dev
shell (`nix develop`) carries ruff and ty so you can run them
ad-hoc.

Fix lint and type errors at the root, never with `# type: ignore`
or silencing. The `CredentialStore.list()` → `entries()` rename was
the lesson: the builtin-shadow broke ty, and the right fix was the
rename, not muting the diagnostic.

## 6. Naming, versioning, releases

* The project, the GitHub repo, the Nix flake attribute, the CLI
  script, and the credentials directory are all `jura-connect`.
* The Python module is `jura_connect` (underscore — Python
  identifier rules).
* The version lives in **three** places. Bump in lockstep:
  * `jura_connect/__init__.py` (`__version__`)
  * `pyproject.toml` (`project.version`)
  * `flake.nix` (`buildPythonPackage.version`)
* SemVer. Breaking changes get a minor (0.X.0) bump while we're 0.y.
* Every release gets a CHANGELOG entry **before** tagging, in
  Keep-A-Changelog format with absolute dates.

Release flow (see README "Releasing" for the full walkthrough):

```sh
$EDITOR jura_connect/__init__.py pyproject.toml flake.nix CHANGELOG.md
nix build .#default                                # verify
git commit -m "jura-connect: release vX.Y.Z"
git push
git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z
gh release create vX.Y.Z --notes-file <(...)       # see README
```

Tagging fires `.github/workflows/publish.yml`, which re-runs the
build gate against the tag before uploading to PyPI via OIDC
trusted-publishing.

## 7. Commit & changelog style

* Kernel-mailing style: subject in imperative, body explains
  **why** not what. The diff already shows what.
* Prefix subjects with `jura-connect: ` (or `README:`, `docs:`,
  `tests:` for narrow changes).
* One logical chunk per commit. Feature commits and release commits
  are separate.
* When risk is non-obvious, mention it in the commit message
  (destructive commands, breaking renames, file deletions).

## 8. Acting safely

* Don't run destructive commands against a real machine "to test"
  — use the simulator.
* Don't push tags or create GitHub releases without explicit
  authorisation in the current turn. The release flow is
  user-initiated by design.
* Don't commit decompiled APK trees, `result` symlinks, or
  `tmp/` scratch. `.gitignore` covers these; if you find untracked
  files outside the gitignored paths, check before adding.
* Don't add `# type: ignore`, `# noqa`, or skip-flags to silence
  diagnostics. Fix the source.

## 9. When in doubt

* The simulator + 319 tests catch most regressions in seconds; lean
  on them.
* `gh search code "<thing> repo:Jutta-Proto/protocol-bt-cpp"`
  finds the Bluetooth-flavour equivalent of most protocol questions.
* The APK's `WifiCommandConnectionSetup`, `WifiCryptoUtil`, and
  `WifiFrog` classes are the original truth for handshake / cipher
  / discovery respectively.
