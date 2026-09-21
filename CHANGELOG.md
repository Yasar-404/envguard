# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-21

First release. Alpha quality: see the known limitations in the README.

### Added

- `envguard scan` for directories and single files, with text, JSON and SARIF 2.1.0 output
  (`--format text|json|sarif`, with `--json` as a shorthand).
- Twelve detection rules: AWS access and secret keys, GitHub tokens, Stripe live keys,
  Google API keys, JWTs, private keys, database URLs, generic API keys, generic secrets,
  password assignments and authorization tokens.
- Confidence scoring from entropy, placeholder detection, structural checks and file context.
- `.gitignore` awareness (via `git ls-files` in repositories, a built-in matcher elsewhere).
- `--history` to scan lines added in Git history, with `--max-commits`. Each secret is
  reported once, at the commit that introduced it.
- `--staged` to scan only the changes staged in Git, and a `.pre-commit-hooks.yaml` manifest
  for the pre-commit framework (3.2 or newer). The hook runs at the `pre-commit` stage only.
- Baseline files: `--write-baseline`, `--baseline` and a `baseline` config option. Findings are
  fingerprinted from rule, file and a hash of the secret.
- `.envguard.toml` configuration and `--exclude`, `--severity`, `--config` options.
- Inline suppression with `envguard:ignore`.
- `envguard rules` to list the detectors.
- Unit tests, integration tests against generated Git repositories, and tests that drive the
  hook through a real `git commit` and through the pre-commit framework (`pre-commit run`,
  `try-repo`, `pre-commit install`). CI runs on Ubuntu and Windows with Python 3.11 to 3.13.

[Unreleased]: https://github.com/Yasar-404/envguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Yasar-404/envguard/releases/tag/v0.1.0
