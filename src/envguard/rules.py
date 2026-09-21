"""Detection rules.

Every pattern has a named `secret` group. The matched value is scored and masked inside
`Rule.find`; callers only ever see the masked form.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from envguard.heuristics import (
    char_classes,
    is_placeholder,
    looks_like_reference,
    shannon_entropy,
)
from envguard.models import Severity

MASK = "*" * 12

Score = Callable[[re.Match[str]], float]


@dataclass(frozen=True)
class Hit:
    rule: Rule
    start: int
    end: int
    confidence: float
    masked: str
    # SHA-256 of the secret, so callers can tell secrets apart without ever seeing one.
    digest: str


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    severity: Severity
    remediation: str
    pattern: re.Pattern[str]
    # Lowercase substrings; the regex only runs on lines containing at least one.
    keywords: tuple[str, ...]
    score: Score
    # How many leading characters of the secret are safe to show (known prefixes).
    keep_prefix: int = 0

    def find(self, line: str, lowered: str) -> Iterator[Hit]:
        if not any(keyword in lowered for keyword in self.keywords):
            return
        for match in self.pattern.finditer(line):
            confidence = self.score(match)
            if confidence > 0:
                yield Hit(
                    self,
                    match.start("secret"),
                    match.end("secret"),
                    confidence,
                    self._mask(match),
                    hashlib.sha256(match["secret"].encode()).hexdigest(),
                )

    def _mask(self, match: re.Match[str]) -> str:
        start, end = match.span("secret")
        offset = match.start()
        text = match.group(0)
        return (
            text[: start - offset] + mask(match["secret"], self.keep_prefix) + text[end - offset :]
        )


def mask(value: str, keep: int = 0) -> str:
    kept = value[:keep]
    return kept if keep >= len(value) else kept + MASK


def _by_entropy(value: str, tiers: tuple[tuple[float, float], ...]) -> float:
    entropy = shannon_entropy(value)
    for minimum, confidence in tiers:
        if entropy >= minimum:
            return confidence
    return 0.0


def _known_format(confidence: float) -> Score:
    def score(match: re.Match[str]) -> float:
        return 0.0 if is_placeholder(match["secret"]) else confidence

    return score


def _score_aws_secret_key(match: re.Match[str]) -> float:
    value = match["secret"]
    return 0.0 if is_placeholder(value) else _by_entropy(value, ((3.7, 0.95),))


def _score_jwt(match: re.Match[str]) -> float:
    header = match["secret"].split(".", 1)[0]
    try:
        decoded = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    except ValueError:
        return 0.0
    return 0.85 if isinstance(decoded, dict) and "alg" in decoded else 0.0


def _score_private_key(match: re.Match[str]) -> float:
    # A header immediately followed by a closing quote is a string being compared against,
    # not the start of embedded key material.
    following = match.string[match.end("secret") : match.end("secret") + 1]
    return 0.4 if following in ("'", '"', "`") else 0.95


_BARE_WORD = re.compile(r"[A-Za-z_]+")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "[::1]"})


def _score_database_url(match: re.Match[str]) -> float:
    if is_placeholder(match["secret"]):
        return 0.0
    host = re.sub(r":\d+$", "", match["host"].lower())
    return 0.4 if host in _LOCAL_HOSTS else 0.9


def _score_keyed_value(match: re.Match[str]) -> float:
    value = match["secret"]
    if is_placeholder(value) or looks_like_reference(value):
        return 0.0
    return _by_entropy(value, ((4.0, 0.75), (3.5, 0.6)))


def _score_password(match: re.Match[str]) -> float:
    value = match["secret"]
    if is_placeholder(value) or looks_like_reference(value):
        return 0.0
    quoted = match.string[match.start("secret") - 1] in "\"'"
    if not quoted and _BARE_WORD.fullmatch(value):
        return 0.0  # an unquoted identifier is a variable or a type, not a literal password
    confidence = (0.6 if quoted else 0.45) + 0.1 * (char_classes(value) - 1)
    return min(confidence, 0.9)


def _score_bearer_token(match: re.Match[str]) -> float:
    value = match["secret"]
    return 0.0 if is_placeholder(value) else _by_entropy(value, ((3.5, 0.85),))


_VALUE = r"""["']?\s*[:=]\s*["']?"""

RULES: tuple[Rule, ...] = (
    Rule(
        id="aws-access-key",
        name="AWS Access Key",
        description="AWS access key ID (AKIA/ASIA/ABIA/ACCA prefix).",
        severity=Severity.HIGH,
        remediation=(
            "Deactivate and rotate the key in IAM, then remove it from the code and from Git "
            "history. Prefer IAM roles or a secrets manager over static keys."
        ),
        pattern=re.compile(
            r"(?<![A-Z0-9])(?P<secret>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})(?![A-Z0-9])"
        ),
        keywords=("akia", "asia", "abia", "acca"),
        score=_known_format(0.95),
        keep_prefix=4,
    ),
    Rule(
        id="aws-secret-key",
        name="AWS Secret Access Key",
        description="Value assigned to an AWS secret access key setting.",
        severity=Severity.HIGH,
        remediation=(
            "Rotate the access key pair in IAM immediately; the secret half cannot be "
            "recovered or revoked separately. Load credentials from the environment or a role."
        ),
        pattern=re.compile(
            r"aws[_-]?secret[_-]?(?:access[_-]?)?key"
            + _VALUE
            + r"(?P<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
            re.IGNORECASE,
        ),
        keywords=("aws",),
        score=_score_aws_secret_key,
    ),
    Rule(
        id="github-token",
        name="GitHub Token",
        description="GitHub personal access, OAuth, app or fine-grained token.",
        severity=Severity.HIGH,
        remediation=(
            "Revoke the token at github.com/settings/tokens and create a replacement with "
            "the minimum scopes. Store it in your CI secret store, not in the repository."
        ),
        pattern=re.compile(
            r"(?<![A-Za-z0-9])(?P<secret>gh[pousr]_[A-Za-z0-9]{36,251}"
            r"|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])"
        ),
        keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
        score=_known_format(0.97),
        keep_prefix=4,
    ),
    Rule(
        id="stripe-secret-key",
        name="Stripe Live Secret Key",
        description="Stripe live-mode secret or restricted API key.",
        severity=Severity.HIGH,
        remediation=(
            "Roll the key in the Stripe dashboard (Developers > API keys) and review recent "
            "API activity for misuse. Load the new key from the environment."
        ),
        pattern=re.compile(
            r"(?<![A-Za-z0-9])(?P<secret>[sr]k_live_[0-9A-Za-z]{24,99})(?![0-9A-Za-z])"
        ),
        keywords=("_live_",),
        score=_known_format(0.97),
        keep_prefix=8,
    ),
    Rule(
        id="google-api-key",
        name="Google API Key",
        description="Google API key (AIza prefix).",
        severity=Severity.MEDIUM,
        remediation=(
            "Delete or regenerate the key in the Google Cloud console and restrict the new "
            "one by API and by referrer or IP address."
        ),
        pattern=re.compile(r"(?<![A-Za-z0-9_-])(?P<secret>AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])"),
        keywords=("aiza",),
        score=_known_format(0.9),
        keep_prefix=4,
    ),
    Rule(
        id="jwt",
        name="JSON Web Token",
        description="Signed JSON Web Token with a decodable header.",
        severity=Severity.MEDIUM,
        remediation=(
            "Treat the token as compromised: invalidate the session or rotate the signing "
            "key if it is long-lived, and remove the token from the code."
        ),
        pattern=re.compile(
            r"(?<![A-Za-z0-9_-])(?P<secret>eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}"
            r"\.[A-Za-z0-9_-]{10,})(?![A-Za-z0-9_-])"
        ),
        keywords=("eyj",),
        score=_score_jwt,
        keep_prefix=3,
    ),
    Rule(
        id="private-key",
        name="Private Key",
        description="PEM or OpenSSH private key block.",
        severity=Severity.HIGH,
        remediation=(
            "Remove the key from the repository and history, generate a new key pair, and "
            "replace the public key wherever it is trusted. Keep private keys in a vault."
        ),
        pattern=re.compile(r"(?P<secret>-----BEGIN (?:[A-Z]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----)"),
        keywords=("private key",),
        score=_score_private_key,
        keep_prefix=100,
    ),
    Rule(
        id="database-url",
        name="Database Connection String",
        description="Connection URL with an embedded password.",
        severity=Severity.HIGH,
        remediation=(
            "Change the database password, then read the connection string from an "
            "environment variable or secrets manager at runtime."
        ),
        pattern=re.compile(
            r"""(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)"""
            r"""://[^\s:/@'"]{0,64}:(?P<secret>[^\s@/'"]{1,128})@(?P<host>[^\s/'"?#]+)"""
        ),
        keywords=("://",),
        score=_score_database_url,
    ),
    Rule(
        id="generic-api-key",
        name="Generic API Key",
        description="High-entropy value assigned to an api_key-style name.",
        severity=Severity.MEDIUM,
        remediation=(
            "Revoke or rotate the key with the provider that issued it and load it from the "
            "environment instead of committing it."
        ),
        pattern=re.compile(
            r"[\w.-]{0,40}api[_-]?key"
            + _VALUE
            + r"(?P<secret>[A-Za-z0-9_\-+/=.]{16,80})(?![A-Za-z0-9_\-+/=.(\[])",
            re.IGNORECASE,
        ),
        keywords=("api",),
        score=_score_keyed_value,
    ),
    Rule(
        id="generic-secret",
        name="Generic Secret",
        description="High-entropy value assigned to a secret-style name.",
        severity=Severity.MEDIUM,
        remediation=(
            "Rotate the secret wherever it is used and load the new value from the "
            "environment or a secrets manager."
        ),
        pattern=re.compile(
            r"[\w.-]{0,40}secret(?:[_-]?key)?"
            + _VALUE
            + r"(?P<secret>[A-Za-z0-9_\-+/=.]{12,80})(?![A-Za-z0-9_\-+/=.(\[])",
            re.IGNORECASE,
        ),
        keywords=("secret",),
        score=_score_keyed_value,
    ),
    Rule(
        id="password-assignment",
        name="Hardcoded Password",
        description="Literal value assigned to a password-style name.",
        severity=Severity.MEDIUM,
        remediation=(
            "Change the password and read it from the environment or a secrets manager. "
            "If it is a test credential, mark the line with `envguard:ignore`."
        ),
        pattern=re.compile(
            r"[\w.-]{0,40}(?:password|passwd)"
            + _VALUE
            + r"""(?P<secret>[^\s"'`,;<>(){}\[\]]{8,64})(?=["'`,;)\s]|$)""",
            re.IGNORECASE,
        ),
        keywords=("password", "passwd"),
        score=_score_password,
    ),
    Rule(
        id="authorization-token",
        name="Authorization Token",
        description="Bearer token or Authorization header value.",
        severity=Severity.HIGH,
        remediation=(
            "Revoke the token with the service that issued it and inject it at runtime "
            "instead of hardcoding it in requests or configuration."
        ),
        pattern=re.compile(
            r"""(?:authorization["']?\s*[:=]\s*["']?(?:bearer|token)|\bbearer)\s+"""
            r"(?P<secret>[A-Za-z0-9._~+/-]{20,}={0,2})",
            re.IGNORECASE,
        ),
        keywords=("bearer", "authorization"),
        score=_score_bearer_token,
    ),
)

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in RULES}
