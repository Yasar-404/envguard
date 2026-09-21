# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- `envguard scan` for directories and single files, with text and JSON output.
- Twelve detection rules: AWS access and secret keys, GitHub tokens, Stripe live keys,
  Google API keys, JWTs, private keys, database URLs, generic API keys, generic secrets,
  password assignments and authorization tokens.
- Confidence scoring from entropy, placeholder detection, structural checks and file context.
- `.gitignore` awareness (via `git ls-files` in repositories, a built-in matcher elsewhere).
- `--history` to scan lines added in Git history, with `--max-commits`.
- `.envguard.toml` configuration and `--exclude`, `--severity`, `--config` options.
- `envguard rules` to list the detectors.
- Inline suppression with `envguard:ignore`.
- Baseline files: `--write-baseline`, `--baseline` and a `baseline` config option. Findings are
  fingerprinted from rule, file and a hash of the secret; the JSON summary gains `baselined`.
- `--staged` mode and a `.pre-commit-hooks.yaml` manifest to block commits that add secrets.

### Fixed

- History scanning no longer merges two different secrets of the same type in one file.
