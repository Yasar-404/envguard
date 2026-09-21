from __future__ import annotations

import enum
from dataclasses import dataclass


class EnvGuardError(Exception):
    """A failure the user can act on; the CLI reports it without a traceback."""


class Severity(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r} (expected low, medium or high)") from None

    def lowered(self) -> Severity:
        return Severity(max(self - 1, Severity.LOW))


@dataclass(frozen=True)
class Finding:
    """A detected secret. Only the masked form of the value is ever stored."""

    rule_id: str
    severity: Severity
    file: str
    line: int
    confidence: float
    masked_value: str
    message: str
    remediation: str
    commit: str | None = None
