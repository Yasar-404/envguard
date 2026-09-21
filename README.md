# EnvGuard

EnvGuard is a command-line scanner that finds credentials committed to source code and Git
repositories: cloud keys, API tokens, private keys, database passwords and similar secrets.
It runs locally, has no runtime dependencies, and never prints a complete secret.

```
$ envguard scan .
EnvGuard Security Scanner

Scanning: .

1 HIGH
1 MEDIUM
0 LOW

HIGH   AWS Access Key
       src/config.py:42
       Confidence: 95%
       Value: AKIA************

       Recommendation:
       Deactivate and rotate the key in IAM, then remove it from the code and from Git
       history. Prefer IAM roles or a secrets manager over static keys.

MEDIUM Hardcoded Password
       ...

Scanned 118 files.
```

## Why it exists

Leaked credentials are one of the most common and most avoidable security incidents, and the
usual fix is a scan that runs before the code leaves the developer's machine or CI runner.
Existing scanners are excellent but often heavy to adopt. EnvGuard aims to be small enough to
read in an afternoon, quick to install, and conservative about false positives, so that
teams keep it switched on.

## Installation

EnvGuard requires Python 3.11 or newer and, for Git features, the `git` executable.
It is not yet published to PyPI; install it from a clone:

```
git clone https://github.com/Yasar-404/envguard.git envguard
cd envguard
python -m pip install .
```

## Quick start

```
envguard scan .                      # scan the working tree
envguard scan ./src                  # scan a subdirectory
envguard scan path/to/file.env       # scan one file
envguard scan . --json               # machine-readable output
envguard scan . --severity high      # only report HIGH findings
envguard scan . --exclude node_modules --exclude "*.svg"
envguard scan . --history            # also scan lines added in Git history
envguard scan . --history --max-commits 500
envguard scan . --write-baseline .envguard-baseline.json   # accept today's findings
envguard scan . --baseline .envguard-baseline.json         # report only new ones
envguard rules                       # list detectors
envguard --help
```

Fix a finding by removing the secret, **rotating it** (it is compromised once committed), and
loading the replacement from the environment or a secrets manager. Removing it from the
latest commit does not remove it from history; `--history` finds copies that remain there.

### Exit codes

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| 0    | Scan completed, no findings                   |
| 1    | Scan completed, findings were reported        |
| 2    | Usage, configuration or runtime error         |

Errors are written to stderr as `envguard: error: <message>`. Findings only count toward the
exit code if they survive the severity and confidence filters described below.

## Detectors

| Rule ID               | Severity | Detects                                                          |
| --------------------- | -------- | ---------------------------------------------------------------- |
| `aws-access-key`      | high     | AWS access key IDs (`AKIA`, `ASIA`, `ABIA`, `ACCA`)              |
| `aws-secret-key`      | high     | Values assigned to an AWS secret access key setting              |
| `github-token`        | high     | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_` tokens   |
| `stripe-secret-key`   | high     | Live-mode `sk_live_` and `rk_live_` keys                         |
| `private-key`         | high     | PEM/OpenSSH/PGP private key headers                              |
| `database-url`        | high     | `postgres://`, `mysql://`, `mongodb://`, `redis://`… with a password |
| `authorization-token` | high     | `Authorization: Bearer …` and similar header values              |
| `google-api-key`      | medium   | `AIza…` API keys                                                 |
| `jwt`                 | medium   | JSON Web Tokens whose header decodes to JSON with `alg`          |
| `generic-api-key`     | medium   | High-entropy values assigned to `api_key`-style names            |
| `generic-secret`      | medium   | High-entropy values assigned to `secret`-style names             |
| `password-assignment` | medium   | Literal values assigned to `password`-style names                |

Stripe test keys, publishable keys and public certificates are deliberately not reported.
`docs/detection.md` explains how each rule scores a match.

## Severity and confidence

Every rule has a severity, and every match gets a confidence between 0 and 1 computed from
what was matched and where.

- A known token format (`AKIA…`, `ghp_…`) starts high. Keyword-based rules such as
  `generic-secret` combine the variable name, the Shannon entropy of the value, and checks
  that reject placeholders (`changeme`, `${VAR}`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`)
  and code references (`self.password`, `os.environ[...]`).
- Files in `tests/`, `docs/`, `examples/`, `fixtures/` and `*.example`/`*.md` files have their
  confidence multiplied by 0.7. `.env*` files get +0.1.
- Matches below `min_confidence` (default 0.5) are dropped.
- A match below 0.6 confidence is reported one severity level lower than its rule's
  severity, so `high` means a well-formed, high-confidence finding.

`--severity` (or `min_severity` in config) filters on the final severity.

Add `envguard:ignore` in a comment on a line to suppress findings on that line.

## Baselines

Adopting a scanner on an existing codebase usually means hundreds of old findings you cannot
fix today. A baseline records them so that only *new* secrets fail the build.

```
envguard scan . --write-baseline .envguard-baseline.json   # writes the file, exits 0
envguard scan . --baseline .envguard-baseline.json         # exits 1 only for new findings
```

or set `baseline = ".envguard-baseline.json"` in `.envguard.toml` so that a plain
`envguard scan .` uses it. Commit the file; entries are sorted, so diffs stay small. Add
`--history` when writing the baseline to include findings in old commits, and pass the same
flag when scanning.

Each entry holds a fingerprint, the rule ID and the file. The fingerprint is a truncated
SHA-256 over the rule, the file path and a hash of the secret, so:

- it survives edits that move the line, and only changes if the secret or file changes;
- two different secrets in one file are tracked separately, so a new key cannot hide behind
  an old one;
- the baseline never contains a secret. A hash of a weak password could in principle be
  brute-forced, but only for a value that is already in your repository.

Suppressed findings are counted in the report (`summary.baselined` in JSON). Entries for
findings that no longer exist are ignored, not an error; regenerate the baseline to prune
them. A rotated secret is a new finding, as it should be, and a renamed file needs its
entries regenerated.

## Configuration

EnvGuard reads `.envguard.toml` from the scanned directory or the nearest parent, stopping at
the repository root. Use `--config PATH` to point elsewhere. Unknown keys are rejected so a
typo cannot silently disable a check.

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

Command-line `--severity` overrides `min_severity`; `--exclude` adds to `exclude`.

### What is scanned

- **In a Git repository**, the file list comes from `git ls-files --cached --others
  --exclude-standard`. Ignored files (including nested `.gitignore`, `.git/info/exclude` and
  your global ignore file) are skipped; tracked files are always scanned, even if they match an
  ignore rule, because a tracked `.env` is exactly the case worth catching.
- **Outside a repository**, EnvGuard walks the directory and applies the root `.gitignore`.
  Nested `.gitignore` files and `!negation` patterns are not supported there.
- Always skipped: `.git`, `node_modules`, virtualenvs, `dist`, `build`, `vendor`, caches,
  lock files, minified bundles and source maps, common binary extensions, files that contain
  NUL bytes, symlinks, files over the size limit and lines over 2000 characters. The default
  exclusions cannot be overridden.
- Files that are not valid UTF-8 are decoded leniently rather than skipped.

### Git history

`--history` runs one `git log --all -p -U0` and scans only the lines each commit added, across
every branch and tag. A secret is reported once, at the commit that introduced it, with its
line number in that commit. Secrets still present in the working tree are reported by the
normal scan and not repeated. History scanning honours `exclude` patterns but not
`.gitignore`, since ignore rules describe today's tree, not the past.

Use `--max-commits N` to bound the work on very large repositories.

## JSON output

```
$ envguard scan . --json
{
  "version": "1",
  "repository": ".",
  "summary": {"high": 1, "medium": 0, "low": 0, "files_scanned": 118, "files_skipped": 2, "baselined": 0},
  "findings": [
    {
      "rule_id": "aws-access-key",
      "severity": "high",
      "file": "src/config.py",
      "line": 42,
      "confidence": 0.95,
      "masked_value": "AKIA************",
      "message": "AWS Access Key",
      "remediation": "Deactivate and rotate the key in IAM, ...",
      "commit": null
    }
  ]
}
```

The schema is versioned and documented in [docs/json-format.md](docs/json-format.md). The
complete secret never appears in it.

## GitHub Actions

`.github/workflows/envguard.yml` in this repository is a working example:

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
          fetch-depth: 0 # needed for --history
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install envguard   # or: pip install .
      - run: envguard scan . --history
```

The job fails when findings exist (exit code 1). Logs contain only masked values.

## Security and privacy

- EnvGuard is fully local. It makes no network requests and sends nothing anywhere.
- The only subprocess it starts is `git`, as an argument list with no shell.
- The complete secret exists only inside the function that scores and masks a match. The
  `Finding` model has no field that could hold it, so text output, JSON, logs and error
  messages cannot contain it. Masking keeps at most a public prefix (`AKIA`, `ghp_`,
  `sk_live_`) and never reveals the length or any trailing characters.
- The test suite builds synthetic credentials at run time from SHA-256 digests; no
  secret-shaped literals are committed.

EnvGuard does not verify whether a detected credential is live. Treat every finding as
compromised until proven otherwise.

## Architecture

```
src/envguard/
    cli.py          argparse front end, config loading, exit codes
    scanner.py      orchestration: file scan, history scan, confidence and severity
    rules.py        Rule model and the twelve detectors (regex + scoring + masking)
    heuristics.py   entropy, placeholder and code-reference checks
    filesystem.py   gitignore-style matcher, file discovery, safe file reading
    git.py          git subprocess wrappers and `git log -p` parsing
    config.py       .envguard.toml loading and validation
    baseline.py     baseline file reading and writing
    reporting.py    text and JSON renderers
    models.py       Severity, Finding, base exception
```

Dependencies point one way: `cli` → `scanner` → `rules`/`filesystem`/`git`. `rules.py` knows
nothing about files. Adding a detector means adding one `Rule`.

Performance choices worth knowing:

- Patterns are compiled once at import. Each rule declares lowercase trigger keywords, and the
  scanner runs one combined search per line, so the per-rule regexes only see the small fraction
  of lines that could contain something (about 10% in the CPython test suite). Checking each
  rule's keywords separately for every line was about 5x slower.
- Files are stat-ed before being read and never read past the size limit; only the first 8 KB
  is sniffed for binary content.
- The file list is one `git ls-files` call; history is one streaming `git log`.

On the author's Windows 10 development machine, the 58 MB CPython 3.13 standard library
(2,667 files) scans in about 8 seconds. Your numbers will vary.

## Development

```
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"

ruff check . && ruff format --check .
mypy
pytest
```

Tests are split into `tests/unit` and `tests/integration`. Integration tests create throwaway
projects and Git repositories under pytest's `tmp_path`, so they need `git` on the PATH and
skip themselves otherwise. Run `envguard scan .` on this repository too: it should be clean.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New detectors need a positive test, at least one
false-positive test and an entry in the detector table.

## Known limitations

- Detection is heuristic. Expect some false positives (documentation examples, test data) and
  some misses (secrets without a recognisable format or variable name, secrets split across
  lines or assembled at run time, key material after a private key header).
- HTTP auth coverage is limited to `Bearer`/`token` values; Basic credentials are not
  detected. There are no detectors yet for Slack, Twilio, npm, PyPI, Azure or GCP
  service-account keys.
- Baseline entries are tied to the file path, so a renamed file resurfaces its findings until
  the baseline is regenerated.
- UTF-16 files are treated as binary. Nested `.gitignore` files are only honoured inside Git
  repositories.
- History scanning ignores merge-commit diffs (as `git log -p` does) and does not follow
  file renames beyond the lines each commit actually changed.

## Roadmap

- SARIF output for GitHub code scanning
- Pre-commit hook and staged-files mode
- More token formats (Slack, Twilio, npm, PyPI, Azure, GCP)
- Parallel file scanning for very large trees

## License

MIT. See [LICENSE](LICENSE).
