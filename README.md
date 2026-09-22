# EnvGuard

A lightweight Python CLI that detects exposed secrets, API keys, tokens and credentials in source code and Git repositories.

[![CI](https://github.com/Yasar-404/envguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Yasar-404/envguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/envguard-scan)](https://pypi.org/project/envguard-scan/)
![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
[![License: MIT](https://img.shields.io/github/license/Yasar-404/envguard)](LICENSE)

Status: alpha. The current release is [v0.1.3](https://github.com/Yasar-404/envguard/releases/tag/v0.1.3); see the [changelog](CHANGELOG.md).

```text
$ envguard scan ./project
EnvGuard Security Scanner

Scanning: ./project

1 HIGH
1 MEDIUM
0 LOW

HIGH   AWS Access Key
       config/settings.py:1
       Confidence: 95%
       Value: AKIA************

       Recommendation:
       Deactivate and rotate the key in IAM, then remove it from the code and
       from Git history. Prefer IAM roles or a secrets manager over static
       keys.

MEDIUM Hardcoded Password
       src/client.py:4
       Confidence: 90%
       Value: API_PASSWORD = "************

       Recommendation:
       Change the password and read it from the environment or a secrets
       manager. If it is a test credential, mark the line with
       `envguard:ignore`.

Scanned 2 files.
```

The exit code is 1 when findings are reported, so the same command works as a CI gate. Only masked values are ever printed.

## Why EnvGuard

Committed credentials are a common and avoidable cause of security incidents, and the practical defence is a scan that runs before code leaves the developer's machine or CI runner. EnvGuard is built around a few constraints:

- Local only. Scanning reads files and runs `git`; nothing is sent anywhere.
- Small enough to adopt. One Python package with no runtime dependencies, ten modules, and rules that are plain data plus a scoring function.
- Conservative about noise. Matches are scored, placeholders and code references are rejected, and low-confidence matches are dropped or downgraded, so a team can leave it switched on.
- Fits the places secrets are caught: the working tree, staged changes in a pre-commit hook, full Git history, and CI.
- Adoptable on an existing codebase through baselines.

## Features

Detection

- Sixteen rules: known credential formats (AWS, GitHub, Stripe, Slack, Twilio, npm, Azure Storage, Google, JWT, private keys) and contextual rules for database URLs, generic API keys, generic secrets, passwords and authorization tokens.
- Regex combined with Shannon entropy, placeholder and code-reference rejection, structural checks and file-path context.
- Per-match confidence score, and severity derived from rule and confidence.

Repository scanning

- Working tree scanning that follows `.gitignore`.
- Git history scanning (`--history`), reporting each secret at the commit that introduced it.
- Staged-change scanning (`--staged`) for commit hooks.
- Binary, oversized, minified and lock files are skipped.

Developer workflow

- Text, JSON and SARIF output.
- Pre-commit hook and CI usage through exit codes.
- `.envguard.toml` configuration, `--exclude` patterns and inline `envguard:ignore`.
- Baseline files that accept existing findings and fail only on new ones.

## Installation

EnvGuard requires Python 3.11 or newer. Git features need the `git` executable on the `PATH`.

```bash
python -m pip install envguard-scan
```

The command and the import package are both named `envguard`; only the distribution on PyPI is called `envguard-scan`, because `envguard` is taken by an unrelated project. Do not run `pip install envguard`: that installs different software. If you installed v0.1.0, which briefly used the distribution name `envguard`, run `pip uninstall envguard` before installing `envguard-scan`.

To install a specific version, a pre-release from `main`, or a clone to work on the source, see [Development](#development) or install directly from GitHub:

```bash
python -m pip install "git+https://github.com/Yasar-404/envguard.git@v0.1.3"
```

## Quick start

```bash
envguard scan .
```

Scans the working tree and prints a report. The exit code is 0 when nothing is found, 1 when findings are reported and 2 on a usage, configuration or runtime error.

| Command | Use it to |
| --- | --- |
| `envguard scan ./src` | Scan a subdirectory. Paths in the report are relative to it. |
| `envguard scan path/to/file.env` | Scan one file. |
| `envguard scan . --severity high` | Report only findings whose final severity is high. |
| `envguard scan . --exclude node_modules --exclude "*.svg"` | Skip paths. Patterns use `.gitignore` syntax and can be repeated. |
| `envguard scan . --history` | Also scan lines added in Git history. Add `--max-commits N` to bound the work. |
| `envguard scan --staged` | Scan only what is staged for the next commit. |
| `envguard scan . --json` | Print a machine-readable JSON report. |
| `envguard scan . --format sarif` | Print a SARIF 2.1.0 report for code scanning tools. |
| `envguard scan . --write-baseline .envguard-baseline.json` | Record today's findings and exit 0. |
| `envguard scan . --baseline .envguard-baseline.json` | Report only findings not in the baseline. |
| `envguard rules` | List the detection rules. |

`envguard --help` and `envguard scan --help` list every option.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Scan completed, no findings |
| 1 | Scan completed, findings were reported |
| 2 | Usage, configuration or runtime error |

Errors are written to stderr as `envguard: error: <message>`. Only findings that survive the severity and confidence filters count toward the exit code.

To fix a finding, remove the secret and rotate it: a committed secret is compromised. Removing it from the latest commit does not remove it from history, and `--history` finds the copies that remain there.

## Detectors

The severity column is the rule's maximum severity. A match with low confidence is reported one level lower (see [Severity and confidence](#severity-and-confidence)).

| Rule ID | Severity | Detects | Approach |
| --- | --- | --- | --- |
| `aws-access-key` | high | AWS access key IDs (`AKIA`, `ASIA`, `ABIA`, `ACCA`) | Known format; rejects placeholders such as the documented `EXAMPLE` key |
| `aws-secret-key` | high | Values assigned to an AWS secret access key setting | Name context, 40-character value, entropy threshold |
| `github-token` | high | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_` tokens | Known format; rejects placeholders |
| `stripe-secret-key` | high | Live-mode `sk_live_` and `rk_live_` keys | Known format; rejects placeholders |
| `slack-token` | high | Slack bot, user, app-level, refresh and workspace tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xapp-`) | Known format; rejects placeholders |
| `twilio-api-key` | high | Twilio API key SID (`SK...`) | Known format; rejects placeholders |
| `npm-token` | high | npm access token (`npm_...`) | Known format; rejects placeholders |
| `azure-storage-key` | high | Azure Storage account key embedded in a connection string (`AccountKey=...`) | Fixed length and charset (86 base64 characters plus `==`); rejects placeholders |
| `private-key` | high | PEM, OpenSSH and PGP private key headers | Header match; lower confidence when the header is a quoted string being compared against |
| `database-url` | high | `postgres://`, `mysql://`, `mongodb://`, `redis://` and similar URLs with a password | URL structure; rejects placeholder passwords; localhost hosts score low |
| `authorization-token` | high | `Authorization: Bearer ...` and similar values | Header context, entropy threshold, placeholder rejection |
| `google-api-key` | medium | `AIza...` API keys | Known format; rejects placeholders |
| `jwt` | medium | JSON Web Tokens | Structure; the header must decode to JSON containing `alg` |
| `generic-api-key` | medium | High-entropy values assigned to `api_key`-style names | Name context, entropy, placeholder and code-reference rejection |
| `generic-secret` | medium | High-entropy values assigned to `secret`-style names | Same as `generic-api-key` |
| `password-assignment` | medium | Literal values assigned to `password`-style names | Name context; quoted values and mixed character classes score higher; unquoted identifiers rejected |

Stripe test keys, publishable keys and public certificates are deliberately not reported. [docs/detection.md](docs/detection.md) gives the exact scoring for each rule.

## Severity and confidence

Severity is what the finding is: a leaked AWS key is high, a hardcoded password is medium. Confidence is how sure EnvGuard is that the match is a real credential, from 0 to 1.

- A known token format such as `AKIA...` or `ghp_...` starts with high confidence. Keyword-based rules combine the variable name, the Shannon entropy of the value (a measure of how random its characters are; real keys score high, words score low) and checks that reject placeholders (`changeme`, `${VAR}`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`) and code references (`self.password`, `os.environ[...]`).
- Files in `tests/`, `docs/`, `examples/`, `fixtures/`, and `*.example` or `*.md` files have their confidence multiplied by 0.7. `.env*` files get +0.1.
- Matches below `min_confidence` (default 0.5) are dropped.
- A match below 0.6 confidence is reported one severity level lower than its rule's severity, so `high` means a well-formed, high-confidence finding.

`--severity` (or `min_severity` in config) filters on the final severity.

## What is scanned

- In a Git repository, the file list comes from `git ls-files --cached --others --exclude-standard`. Ignored files, including nested `.gitignore`, `.git/info/exclude` and your global ignore file, are skipped. Tracked files are always scanned even if they match an ignore rule, because a tracked `.env` is exactly the case worth catching.
- Outside a repository, EnvGuard walks the directory and applies the root `.gitignore`. Nested `.gitignore` files and `!negation` patterns are not supported there.
- Always skipped: `.git`, `node_modules`, virtualenvs, `dist`, `build`, `vendor`, caches, lock files, minified bundles and source maps, common binary extensions, files containing NUL bytes, symlinks, files over the size limit and lines over 2000 characters. The default exclusions cannot be overridden.
- Files that are not valid UTF-8 are decoded leniently rather than skipped.

### Git history

`--history` runs one `git log --all -p -U0` and scans only the lines each commit added, across every branch and tag. A secret is reported once, at the commit that introduced it, with its line number in that commit. Secrets still present in the working tree are reported by the normal scan and not repeated. History scanning honours `exclude` patterns but not `.gitignore`, since ignore rules describe today's tree, not the past.

Use `--max-commits N` to bound the work on very large repositories.

### Staged changes

`--staged` runs `git diff --cached` and scans only the lines added by the staged changes. It reads the index, not the working tree, so it checks exactly what is about to be committed: a secret that was staged and then deleted from the file on disk is still reported. It honours `exclude`, `--baseline` and `envguard:ignore`, and cannot be combined with `--history`.

## Suppressing findings

Three mechanisms, from narrowest to broadest:

- Add `envguard:ignore` in a comment on a line to suppress findings on that line.
- Add patterns to `exclude` in `.envguard.toml`, or pass `--exclude`.
- Use a baseline to accept everything that exists today.

### Baselines

Adopting a scanner on an existing codebase usually means many old findings you cannot fix immediately. A baseline records them so that only new secrets fail the build.

```bash
envguard scan . --write-baseline .envguard-baseline.json   # writes the file, exits 0
envguard scan . --baseline .envguard-baseline.json         # exits 1 only for new findings
```

You can also set `baseline = ".envguard-baseline.json"` in `.envguard.toml` so that a plain `envguard scan .` uses it. Commit the file; entries are sorted, so diffs stay small. Add `--history` when writing the baseline to include findings in old commits, and pass the same flag when scanning.

Each entry holds a fingerprint, the rule ID and the file. The fingerprint is a truncated SHA-256 over the rule, the file path and a hash of the secret, so:

- it survives edits that move the line, and only changes if the secret or file changes;
- two different secrets in one file are tracked separately, so a new key cannot hide behind an old one;
- the baseline never contains a secret. A hash of a weak password could in principle be brute-forced, but only for a value that is already in your repository.

Suppressed findings are counted in the report (`summary.baselined` in JSON). Entries for findings that no longer exist are ignored, not an error; regenerate the baseline to prune them. A rotated secret is a new finding, and a renamed file needs its entries regenerated.

## Configuration

EnvGuard reads `.envguard.toml` from the scanned directory or the nearest parent, stopping at the repository root. Use `--config PATH` to point elsewhere. All keys are top-level and optional. Unknown keys are rejected so a typo cannot silently disable a check.

```toml
# Gitignore-style patterns, relative to the scanned directory.
exclude = ["docs/", "vendor/", "*.svg"]

# Rule IDs from `envguard rules`.
disable_rules = ["generic-secret"]

# Minimum severity to report: low, medium or high.
min_severity = "low"

# Drop matches below this confidence (0 to 1).
min_confidence = 0.5

# Files larger than this are skipped.
max_file_size_kb = 1024

# Baseline file of accepted findings, relative to this config file.
baseline = ".envguard-baseline.json"
```

Command-line `--severity` overrides `min_severity`, and `--exclude` adds to `exclude`.

## Pre-commit hook

`envguard scan --staged` is designed for commit hooks. It scans the lines added by the changes staged in Git, read from the index, so it checks what is about to be committed. With the [pre-commit](https://pre-commit.com) framework (3.2 or newer), add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Yasar-404/envguard
    rev: v0.1.3
    hooks:
      - id: envguard
```

Options go in `args`, for example `args: ["--exclude", "generated/"]` or `args: ["--baseline", ".envguard-baseline.json"]`.

The hook runs only at the `pre-commit` stage and deliberately ignores the file list pre-commit passes (`pass_filenames: false`). pre-commit temporarily stashes unstaged changes while hooks run, and EnvGuard reads the staged diff, so a partially staged file is checked exactly as it will be committed. Consequences:

- A secret that is only in the working tree or in unstaged edits does not block a commit; it is checked when it is staged.
- `pre-commit run --all-files` and `--files` do not widen the scan. They report a pass when nothing is staged, so they are not a substitute for a CI scan. Use `envguard scan .` in CI.
- Pure deletions and pure renames add no lines and are not scanned. A file staged with a secret added during the rename is.

pre-commit builds an isolated environment for the hook, so the first run needs network access to install EnvGuard. If EnvGuard is already installed, a local hook avoids that:

```yaml
repos:
  - repo: local
    hooks:
      - id: envguard
        name: envguard
        entry: envguard scan --staged
        language: system
        pass_filenames: false
```

Without the framework, save this as `.git/hooks/pre-commit` and make it executable:

```sh
#!/bin/sh
exec envguard scan --staged
```

A commit with findings is blocked and the masked report is shown. Fix the secret, rotate it, and commit again. `git commit --no-verify` skips the hook, so keep a CI scan as the backstop.

Validation status:

- The plain Git hook above is covered by a test that installs a real `.git/hooks/pre-commit` script and checks that `git commit` is blocked or allowed.
- The framework path is covered by `tests/integration/test_precommit.py`. It copies the current sources into a temporary Git repository, points a `.pre-commit-config.yaml` at it and drives the real tools: `pre-commit run`, `pre-commit try-repo`, and `git commit` after `pre-commit install`. It checks that a staged synthetic secret fails the hook and blocks the commit with masked output, that clean and unstaged content passes, and that hook `args` are honoured. The test needs network access to build the hook environment and skips itself if `pre-commit` is not installed.
- `try-repo` only sees staged changes too: `pre-commit try-repo <repo> envguard --files secret.env` passes unless `secret.env` has been staged with `git add`.
- Not tested: macOS, and pre-commit versions other than the ones CI installs.

## GitHub Actions

Run EnvGuard in CI and fail the build on findings. The job fails on exit code 1:

```yaml
name: EnvGuard
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # needed for --history
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install envguard-scan==0.1.3
      - run: envguard scan . --history
```

The install is pinned to a version so CI is reproducible; drop `==0.1.3` to track the latest release. Logs contain only masked values. [.github/workflows/envguard.yml](.github/workflows/envguard.yml) is the equivalent workflow this repository runs against itself, installing from the checkout. Use `--history` only with `fetch-depth: 0`; drop it for a working-tree-only scan.

To upload results to GitHub code scanning, see [SARIF output](#sarif).

## Output formats

### JSON

`--json` (or `--format json`) is intended for CI, automation and integrations.

```json
{
  "version": "1",
  "repository": ".",
  "summary": {
    "high": 1,
    "medium": 0,
    "low": 0,
    "files_scanned": 118,
    "files_skipped": 2,
    "baselined": 0
  },
  "findings": [
    {
      "rule_id": "aws-access-key",
      "severity": "high",
      "file": "src/config.py",
      "line": 42,
      "confidence": 0.95,
      "masked_value": "AKIA************",
      "message": "AWS Access Key",
      "remediation": "Deactivate and rotate the key in IAM, then remove it from the code and from Git history. Prefer IAM roles or a secrets manager over static keys.",
      "commit": null
    }
  ]
}
```

`commit` is the full commit hash for findings from `--history` and `null` otherwise. The complete secret never appears in the report. The schema is versioned and documented in [docs/json-format.md](docs/json-format.md).

### SARIF

`--format sarif` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) report that GitHub code scanning and other SARIF viewers understand.

| EnvGuard | SARIF |
| --- | --- |
| rule | `tool.driver.rules[]`, with the remediation as `help` and a `security-severity` |
| high / medium / low | result `level` `error` / `warning` / `note` |
| file, line | `physicalLocation` with a percent-encoded relative `uri` and `startLine` |
| masked value | in the message and `properties.maskedValue` |
| confidence, commit | `properties.confidence`, `properties.commit` |

Every rule is listed in the report whether or not it fired. The report contains only masked values and no fingerprints: EnvGuard does not emit `partialFingerprints`, so GitHub derives its own de-duplication hash from file contents, and no hash of a secret leaves your machine.

Paths are relative to the scanned directory, and code scanning expects paths relative to the repository root, so scan from the root (`envguard scan .`). Locations of `--history` findings refer to the commit that added the secret and may not exist in the checked-out tree.

To upload results to GitHub code scanning:

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install envguard-scan==0.1.3
      # Exit code 1 (findings) should not stop the upload; anything else is a real error.
      - run: envguard scan . --format sarif > envguard.sarif || test $? -eq 1
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: envguard.sarif
```

Code scanning needs a public repository or GitHub Code Security on a private one. Because this job succeeds when findings exist, keep a plain `envguard scan .` step if you also want the build to fail.

Validation status: a generated report was checked against the official SARIF 2.1.0 JSON schema, and the format is covered by unit and CLI tests. That schema check was manual and is not part of CI. Uploading a report to GitHub code scanning has not been tested.

## Security and privacy

- Scanning is local. The package has no network code and no runtime dependencies. The only external program it runs is `git`, as an argument list with no shell, and only for file listing, history and staged diffs. It passes `--no-ext-diff` and `--no-textconv` to diff-producing commands.
- Scanned content is never sent anywhere. There are no telemetry, update checks or API calls.
- The complete secret exists only while a match is scored and masked inside `Rule.find`. The `Finding` model has no field that could hold it, so text output, JSON and SARIF reports cannot contain it. Masking keeps at most a public prefix (`AKIA`, `ghp_`, `sk_live_`), replaces the rest with a fixed-length mask, and does not reveal the secret's length.
- The masked value can include surrounding text from the line: the variable name, and for database URLs the scheme, user and host.
- EnvGuard has no logging or debug output. Its output is the report on stdout and one-line errors on stderr. Error messages name files and settings, not scanned content.
- A SHA-256 digest of each secret is kept in memory to compute fingerprints. Fingerprints are written only to baseline files, which never contain the secret. They are not included in JSON or SARIF reports.
- The test suite builds its fake credentials at run time from SHA-256 digests, so no secret-shaped literals are committed. The repository scans itself in CI and in the test suite.

EnvGuard does not verify whether a detected credential is live. Treat every finding as compromised. It has not had an independent security review.

## Architecture

```text
src/envguard/
    cli.py          argparse front end, config loading, exit codes
    scanner.py      orchestration: tree, history and staged scans; confidence and severity
    rules.py        Rule model and the twelve detectors (regex, scoring, masking)
    heuristics.py   entropy, placeholder and code-reference checks
    filesystem.py   gitignore-style matcher, file discovery, safe file reading
    git.py          git subprocess wrappers and diff parsing
    config.py       .envguard.toml loading and validation
    baseline.py     baseline file reading and writing
    reporting.py    text, JSON and SARIF renderers
    models.py       Severity, Finding, base exception
tests/
    unit/           rules, scoring, filesystem, config, baseline, reporting
    integration/    CLI, Git repositories, history, staged scans, hooks
docs/               detection scoring, JSON format
```

Dependencies point one way: `cli` calls `scanner`, which uses `rules`, `filesystem` and `git`. `rules.py` knows nothing about files. Adding a detector means adding one `Rule` with a pattern, trigger keywords, a scoring function and remediation text.

### Performance

There is no formal benchmark suite. What has been measured and what is design intent:

- Measured, during development: the 58 MB CPython 3.13 standard library (2,667 files) scans in about 8 seconds on the author's Windows 10 machine, in a single process. This was measured before baselines, staged scanning and SARIF were added and has not been repeated since. Timings will vary.
- Measured: an earlier version that checked each rule's keywords separately for every line took about 37 seconds on the same corpus. Replacing it with one combined keyword search per line gave about a 5x speedup with identical findings. About 10% of lines in that corpus reach the per-rule regexes.
- Design: patterns are compiled once at import; files are stat-ed before being read and never read past the size limit; only the first 8 KB is sniffed for binary content; the file list is one `git ls-files` call; history is one streaming `git log`.

## Testing

The suite has 274 tests. 273 pass and 1 is skipped on Windows, where creating symlinks needs elevated rights. The pre-commit framework tests take about a minute on their own because pre-commit builds a virtualenv for the hook.

- Unit tests cover every rule with positive and false-positive cases, masking, confidence and severity calculation, path-context adjustments, `.gitignore` and exclude matching, binary, oversized and malformed files, configuration validation, baselines and the report formats.
- Integration tests run the CLI against generated fixture projects and throwaway Git repositories: exit codes, JSON and SARIF output, `.gitignore` behaviour, history scanning, staged scanning, baselines, a real `.git/hooks/pre-commit` script and the hook installed through the pre-commit framework. Fixtures are built at run time under `tmp_path`, using synthetic credentials.
- A test scans this repository and expects no findings.

CI (GitHub Actions) runs on Ubuntu and Windows with Python 3.11, 3.12 and 3.13: `ruff check`, `ruff format --check`, `mypy` in strict mode and `pytest`, followed by a package build checked with `twine check`. All six matrix jobs and the build passed on `main` at the time of writing. macOS is not tested.

## Known limitations

- Detection is heuristic. Expect some false positives (documentation examples, test data) and some misses: secrets without a recognisable format or variable name, secrets split across lines or assembled at run time, and key material after a private key header.
- Entropy thresholds are reasoned, not tuned on a labelled corpus, so precision and recall have not been measured. Entropy checks can miss low-entropy real secrets and flag high-entropy identifiers.
- HTTP auth coverage is limited to `Bearer` and `token` values; Basic credentials are not detected. There are no detectors yet for PyPI or GCP service-account keys. Twilio's Account SID (not secret) and Auth Token (no distinguishing prefix, so not reliably matchable) are not detected, only the API key SID. Azure Active Directory / service principal client secrets have no fixed format and are only caught, if named accordingly, by the generic `secret`-keyword rule; only the Storage account key is detected directly. Legacy UUID-style npm tokens have no distinguishing format and are not detected, only the newer `npm_`-prefixed ones.
- Baseline entries are tied to the file path, so a renamed file resurfaces its findings until the baseline is regenerated.
- UTF-16 files are treated as binary. Nested `.gitignore` files are only honoured inside Git repositories.
- History scanning ignores merge-commit diffs (as `git log -p` does) and does not follow file renames beyond the lines each commit actually changed. It has not been run on very large repositories.
- `git commit --no-verify` bypasses the pre-commit hook, and the hook only inspects staged changes, so `pre-commit run --all-files` does not scan the tree.
- Scanning is single-threaded.

## Roadmap

- More token formats (PyPI, GCP).
- Parallel file scanning for very large trees.

## Development

```bash
git clone https://github.com/Yasar-404/envguard.git
cd envguard
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"

ruff check . && ruff format --check .
mypy
pytest
envguard scan .               # the repository should scan clean
```

Integration tests create throwaway projects and Git repositories under pytest's `tmp_path`, so they need `git` on the `PATH` and skip themselves otherwise. The pre-commit framework tests also need the `pre-commit` package (part of the `dev` extra) and network access for the first hook environment build.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the rules for test data (no real secrets, ever) and how to add a detector: a new rule needs a positive test, at least one false-positive test and an entry in the detector table.

## License

MIT. See [LICENSE](LICENSE).
