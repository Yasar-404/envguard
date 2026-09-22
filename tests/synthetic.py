"""Synthetic credentials for tests.

Values are derived from SHA-256 of a fixed label, so they are deterministic, look random to the
detectors, and can never be a real credential. They are built at runtime rather than written
out, which also keeps secret-shaped literals out of the repository.
"""

from __future__ import annotations

import base64
import hashlib
import json
import string

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
BASE64 = ALNUM + "/+"
URLSAFE = ALNUM + "_-"
HEX = string.digits + "abcdef"


def synthetic(length: int, label: str, alphabet: str = ALNUM) -> str:
    chars: list[str] = []
    counter = 0
    while len(chars) < length:
        digest = hashlib.sha256(f"{label}:{counter}".encode()).digest()
        chars.extend(alphabet[byte % len(alphabet)] for byte in digest)
        counter += 1
    return "".join(chars[:length])


def aws_access_key() -> str:
    return "AKIA" + synthetic(16, "aws-access", UPPER_DIGITS)


def aws_secret_key() -> str:
    return synthetic(40, "aws-secret", BASE64)


def github_token() -> str:
    return "ghp_" + synthetic(36, "github")


def stripe_key() -> str:
    return "sk_live_" + synthetic(24, "stripe")


def google_key() -> str:
    return "AIza" + synthetic(35, "google", URLSAFE)


def slack_bot_token() -> str:
    return "xoxb-" + synthetic(24, "slack-bot")


def slack_app_token() -> str:
    return (
        "xapp-1-"
        + synthetic(10, "slack-app-id", UPPER_DIGITS)
        + "-"
        + synthetic(13, "slack-app-num", string.digits)
        + "-"
        + synthetic(32, "slack-app-secret", HEX)
    )


def twilio_api_key() -> str:
    return "SK" + synthetic(32, "twilio-api-key", HEX)


def _b64url(payload: dict[str, str]) -> str:
    raw = json.dumps(payload).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwt() -> str:
    header = _b64url({"alg": "HS256", "typ": "JWT"})
    claims = _b64url({"sub": "synthetic-user"})
    return f"{header}.{claims}.{synthetic(43, 'jwt-signature', URLSAFE)}"


def private_key_header() -> str:
    return "-----BEGIN RSA " + "PRIVATE KEY-----"


def db_password() -> str:
    return synthetic(14, "db-password")


def api_key() -> str:
    return synthetic(32, "api-key")


def generic_secret() -> str:
    return synthetic(32, "generic-secret")


def bearer_token() -> str:
    return synthetic(40, "bearer", URLSAFE)
