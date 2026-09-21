# JSON report format

`envguard scan --json` prints one JSON document to stdout. Errors go to stderr, never into the
document, so stdout is safe to pipe into `jq` or a CI step. The exit code is the same as for
text output.

## Stability

`version` is `"1"`. Within a schema version, keys are only ever added, never renamed, removed
or retyped. A breaking change bumps the version.

## Document

| Key          | Type   | Description                                                        |
| ------------ | ------ | ------------------------------------------------------------------ |
| `version`    | string | Schema version.                                                    |
| `repository` | string | The path argument exactly as given on the command line.            |
| `summary`    | object | Counts, see below.                                                 |
| `findings`   | array  | Findings, ordered by severity (high first), file, line, rule, commit. |

### `summary`

| Key             | Type    | Description                                                |
| --------------- | ------- | ---------------------------------------------------------- |
| `high`          | integer | Findings with severity `high`.                             |
| `medium`        | integer | Findings with severity `medium`.                           |
| `low`           | integer | Findings with severity `low`.                              |
| `files_scanned` | integer | Files read and scanned in the working tree.                |
| `files_skipped` | integer | Files that could not be scanned: binary, too large, unreadable, symlinks. |
| `baselined`     | integer | Findings suppressed because they are recorded in the baseline. |

### Finding

| Key            | Type            | Description                                                    |
| -------------- | --------------- | -------------------------------------------------------------- |
| `rule_id`      | string          | Stable rule identifier, as listed by `envguard rules`.         |
| `severity`     | string          | `high`, `medium` or `low`, after confidence adjustment.        |
| `file`         | string          | Path relative to the scanned directory, `/`-separated.         |
| `line`         | integer         | 1-based line number. For history findings, the line in that commit's version of the file. |
| `confidence`   | number          | 0 to 1, rounded to two decimals.                               |
| `masked_value` | string          | The matching text with the secret replaced by `************`. A known public prefix such as `AKIA` may remain. |
| `message`      | string          | Short name of the detected credential type.                    |
| `remediation`  | string          | What to do about it.                                           |
| `commit`       | string or null  | Full commit hash for findings from `--history`; `null` for working-tree findings. |

## Example

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
      "rule_id": "database-url",
      "severity": "high",
      "file": "config/settings.py",
      "line": 12,
      "confidence": 0.9,
      "masked_value": "postgres://app:************@db.internal:5432",
      "message": "Database Connection String",
      "remediation": "Change the database password, then read the connection string from an environment variable or secrets manager at runtime.",
      "commit": null
    }
  ]
}
```

## Guarantees

The complete secret value is never present anywhere in the document. `masked_value` is built
from the surrounding text of the match (variable name, URL scheme, host) plus a fixed-length
mask, so it does not reveal the length of the secret.
