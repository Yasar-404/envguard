from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from envguard.models import EnvGuardError, Severity
from envguard.rules import RULES_BY_ID

CONFIG_FILENAME = ".envguard.toml"


class ConfigError(EnvGuardError):
    pass


@dataclass(frozen=True)
class Config:
    exclude: tuple[str, ...] = ()
    disable_rules: frozenset[str] = frozenset()
    min_severity: Severity = Severity.LOW
    min_confidence: float = 0.5
    max_file_size: int = 1024 * 1024


def find_config(start: Path) -> Path | None:
    """Look for a config file in `start` and its parents, stopping at the repository root."""
    for directory in (start, *start.parents):
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        if (directory / ".git").exists():
            return None
    return None


def load_config(path: Path) -> Config:
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    try:
        return _build(raw)
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from None


def _build(raw: dict[str, Any]) -> Config:
    known = {"exclude", "disable_rules", "min_severity", "min_confidence", "max_file_size_kb"}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(f"unknown option(s): {', '.join(unknown)}")

    defaults = Config()
    disabled = _string_list(raw, "disable_rules")
    missing = sorted(set(disabled) - set(RULES_BY_ID))
    if missing:
        raise ConfigError(f"unknown rule id(s) in disable_rules: {', '.join(missing)}")

    min_severity = defaults.min_severity
    if "min_severity" in raw:
        try:
            min_severity = Severity.parse(str(raw["min_severity"]))
        except ValueError as exc:
            raise ConfigError(f"min_severity: {exc}") from None

    return Config(
        exclude=tuple(_string_list(raw, "exclude")),
        disable_rules=frozenset(disabled),
        min_severity=min_severity,
        min_confidence=_number(raw, "min_confidence", defaults.min_confidence, 0.0, 1.0),
        max_file_size=int(
            _number(raw, "max_file_size_kb", defaults.max_file_size / 1024, 1, 1_000_000) * 1024
        ),
    )


def _string_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{key} must be a list of strings")
    return value


def _number(raw: dict[str, Any], key: str, default: float, low: float, high: float) -> float:
    if key not in raw:
        return default
    value = raw[key]
    if isinstance(value, bool) or not isinstance(value, int | float) or not low <= value <= high:
        raise ConfigError(f"{key} must be a number between {low:g} and {high:g}")
    return float(value)
