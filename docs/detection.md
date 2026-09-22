# How detection works

Each line of a file is checked in three steps.

1. **Trigger.** Every rule lists lowercase keywords (`akia`, `://`, `secret`, ...). One compiled
   alternation of all active keywords is searched per line; lines with no hit are done.
2. **Match and score.** For each rule whose keywords occur, its regex runs. The regex must
   capture the sensitive value in a group named `secret`. A scoring function then returns a
   confidence, or 0 to reject the match.
3. **Adjust and filter.** Overlapping matches from different rules keep the strongest one.
   Path context adjusts confidence, severity is derived from confidence, and the configured
   thresholds are applied.

## Scoring per rule

| Rule                  | Confidence                                                                    |
| --------------------- | ----------------------------------------------------------------------------- |
| `aws-access-key`      | 0.95, or rejected if the value is a placeholder (e.g. contains `EXAMPLE`).    |
| `aws-secret-key`      | 0.95 if the 40-character value has entropy of at least 3.7 bits, else rejected. |
| `github-token`        | 0.97 unless a placeholder.                                                    |
| `stripe-secret-key`   | 0.97 unless a placeholder. Only live keys match.                              |
| `slack-token`         | 0.95 unless a placeholder.                                                    |
| `twilio-api-key`      | 0.90 unless a placeholder.                                                    |
| `npm-token`           | 0.95 unless a placeholder.                                                    |
| `azure-storage-key`   | 0.90 unless a placeholder.                                                    |
| `google-api-key`      | 0.90 unless a placeholder.                                                    |
| `jwt`                 | 0.85 if the header segment decodes to a JSON object containing `alg`; else rejected. |
| `private-key`         | 0.95. 0.40 if the header is immediately followed by a closing quote (a string being compared against). |
| `database-url`        | 0.90. 0.40 for `localhost`, `127.0.0.1`, `0.0.0.0` and `[::1]`. Placeholder passwords (`password`, `${VAR}`, ...) rejected. |
| `generic-api-key`     | 0.75 at entropy >= 4.0, 0.60 at >= 3.5, else rejected. Placeholders and code references rejected. |
| `generic-secret`      | Same as `generic-api-key`.                                                    |
| `password-assignment` | Starts at 0.60 if quoted, 0.45 if not; +0.10 for each extra character class (lowercase, uppercase, digit, other), capped at 0.90. Unquoted identifiers, placeholders and code references rejected. |
| `authorization-token` | 0.85 at entropy >= 3.5 unless a placeholder.                                  |

A value counts as a **placeholder** if it is a common dummy (`password`, `admin`, `test`, ...),
starts like a template reference (`$`, `{`, `<`, `%s`), contains a marker such as `example`,
`changeme`, `your_`, `xxxx` or `redacted`, or uses four or fewer distinct characters.

A value counts as a **code reference** if it is a dotted attribute chain (`config.db.password`)
or a lowercase snake_case identifier (`db_password`).

## Path context

| Path                                                                 | Effect          |
| -------------------------------------------------------------------- | --------------- |
| Directory named `test`, `tests`, `__tests__`, `spec`, `fixtures`, `testdata`, `example(s)`, `doc(s)`; file ending `.example`, `.sample`, `.template`, `.dist`, `.md`, `.rst` | confidence x 0.7 |
| File name starting with `.env`                                       | confidence + 0.1 |

## Severity

The rule's severity is a ceiling. If the final confidence is below 0.6 the finding is
reported one level lower (high to medium, medium to low). Findings below `min_confidence`
(default 0.5) are dropped before severity filtering.

## Adding a rule

Add a `Rule` to `RULES` in `src/envguard/rules.py` with a pattern containing a `(?P<secret>...)`
group, a keyword tuple, a scoring function and remediation text. Then add tests as described
in CONTRIBUTING.md.

## Known blind spots

Line-based scanning cannot see secrets split over several lines, and a private key is
reported from its header line only. Values built at run time or read from another file are
invisible by design. Entropy-based rules can miss low-entropy real secrets and flag
high-entropy identifiers.
