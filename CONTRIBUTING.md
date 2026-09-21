# Contributing

Bug reports and pull requests are welcome. For anything larger than a bug fix or a new
detector, please open an issue first so we can agree on the approach.

## Setup

```
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

Before pushing:

```
ruff check . && ruff format --check .
mypy
pytest
envguard scan .
```

CI runs the same checks on Linux and Windows for Python 3.11 to 3.13. The last command is
also a check on the tests: the repository must scan clean.

## Ground rules

- **No real secrets, ever**, including in issues and pull requests. Tests use
  `tests/synthetic.py`, which derives values from SHA-256 so they are deterministic and cannot
  be real. Build secret-shaped values at run time rather than writing them as literals. If a
  test needs a literal that trips the scanner, mark that line `envguard:ignore`.
- **Never widen what leaves the scanner.** `Finding` must not gain a field that can hold an
  unmasked value, and no code path may log, print or raise with matched text.
- Keep it small. Prefer a plain function to a class, and no new runtime dependencies without
  a strong reason.
- Public behaviour changes (CLI flags, exit codes, JSON keys, rule IDs) need a CHANGELOG entry.
  Rule IDs and JSON keys are stable; do not rename them.

## Adding or changing a detector

1. Add or edit the `Rule` in `src/envguard/rules.py`. The pattern needs a `secret` group,
   bounded quantifiers (no unbounded nesting), and a keyword tuple that every matching line
   is guaranteed to contain.
2. Put the scoring logic in a small function next to the others. Reject placeholders and code
   references rather than lowering their confidence.
3. In `tests/unit/test_rules.py` add at least one positive case (which also checks masking)
   and at least one false-positive case that is realistic.
4. Update the detector table in `README.md` and, if scoring changed, `docs/detection.md`.
5. Run the rule against a large real codebase you have permission to scan and look at what it
   reports before opening the pull request.

## Commit and PR style

Small, focused commits with an imperative subject line. Explain the reason for a change in
the body when it is not obvious. Pull requests should describe the behaviour change and how
it was tested.

## Reporting security issues

If you find a way to make EnvGuard leak a scanned secret, or to execute code through a
crafted repository, please report it privately to the maintainers instead of opening a
public issue.
