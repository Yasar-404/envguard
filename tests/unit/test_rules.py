import pytest

import synthetic as fake
from envguard.models import Severity
from envguard.rules import MASK, RULES, RULES_BY_ID, mask

DEFAULT_MIN_CONFIDENCE = 0.5

# Deliberately fake literals; the marker keeps the repository's own scan clean.
QUOTED_PASSWORD = 'db_password = "Sup3r-Secret!"'  # envguard:ignore
QUOTED_WORD = 'password = "hunterhunter"'  # envguard:ignore
QUOTED_MIXED = 'password = "Hunter2hunter!"'  # envguard:ignore


def detect(rule_id, line):
    """Hits that would survive the default confidence threshold."""
    hits = RULES_BY_ID[rule_id].find(line, line.lower())
    return [hit for hit in hits if hit.confidence >= DEFAULT_MIN_CONFIDENCE]


def test_rule_ids_are_unique_and_documented():
    assert len({rule.id for rule in RULES}) == len(RULES)
    for rule in RULES:
        assert rule.name and rule.description and rule.remediation


def test_every_pattern_has_a_secret_group():
    for rule in RULES:
        assert "secret" in rule.pattern.groupindex, rule.id


# (rule id, line containing a synthetic credential, the credential)
def positive_cases():
    aws_key, aws_secret = fake.aws_access_key(), fake.aws_secret_key()
    gh, stripe, google = fake.github_token(), fake.stripe_key(), fake.google_key()
    slack_bot, slack_app = fake.slack_bot_token(), fake.slack_app_token()
    twilio = fake.twilio_api_key()
    token, pw = fake.jwt(), fake.db_password()
    api, secret, bearer = fake.api_key(), fake.generic_secret(), fake.bearer_token()
    return [
        ("aws-access-key", f'aws_access_key_id = "{aws_key}"', aws_key),
        ("aws-access-key", f"AWS_ACCESS_KEY_ID={aws_key}", aws_key),
        ("aws-secret-key", f"AWS_SECRET_ACCESS_KEY={aws_secret}", aws_secret),
        ("aws-secret-key", f'"aws_secret_access_key": "{aws_secret}"', aws_secret),
        ("github-token", f"GITHUB_TOKEN={gh}", gh),
        ("github-token", "token: github_pat_" + fake.synthetic(30, "pat", fake.ALNUM + "_"), None),
        ("stripe-secret-key", f'stripe.api_key = "{stripe}"', stripe),
        ("slack-token", f'SLACK_BOT_TOKEN = "{slack_bot}"', slack_bot),
        ("slack-token", f"app_token: {slack_app}", slack_app),
        ("twilio-api-key", f'TWILIO_API_KEY = "{twilio}"', twilio),
        ("google-api-key", f"GOOGLE_KEY: {google}", google),
        ("jwt", f'const session = "{token}";', token),
        ("private-key", fake.private_key_header(), None),
        ("private-key", f'KEY = "{fake.private_key_header()}\\nMIIE..."', None),
        ("database-url", f"DATABASE_URL=postgres://app:{pw}@db.internal.test:5432/app", pw),
        ("database-url", f'uri = "mongodb+srv://svc:{pw}@cluster0.test.mongodb.net/x"', pw),
        ("generic-api-key", f'api_key = "{api}"', api),
        ("generic-api-key", f"X_API_KEY: {api}", api),
        ("generic-secret", f"client_secret: {secret}", secret),
        ("generic-secret", f"SECRET_KEY = '{secret}'", secret),
        ("password-assignment", QUOTED_PASSWORD, "Sup3r-Secret!"),  # envguard:ignore
        ("password-assignment", "PASSWORD=Hunter2Hunter2", "Hunter2Hunter2"),
        ("authorization-token", f'headers = {{"Authorization": "Bearer {bearer}"}}', bearer),
        ("authorization-token", f"curl -H 'Authorization: token {bearer}'", bearer),
    ]


@pytest.mark.parametrize(("rule_id", "line", "secret"), positive_cases())
def test_detects_and_masks(rule_id, line, secret):
    hits = detect(rule_id, line)
    assert len(hits) == 1, f"{rule_id} did not match"
    if secret is not None:
        assert secret not in hits[0].masked
        assert MASK in hits[0].masked


@pytest.mark.parametrize(
    ("rule_id", "line"),
    [
        # documented example key from AWS docs
        ("aws-access-key", "AKIAIOSFODNN7EXAMPLE"),
        ("aws-access-key", "key = AKIA" + "X" * 16),
        ("aws-access-key", "AKIA" + fake.synthetic(17, "too-long", fake.UPPER_DIGITS)),
        ("aws-secret-key", "AWS_SECRET_ACCESS_KEY=" + "a" * 40),
        ("aws-secret-key", "AWS_SECRET_ACCESS_KEY=${AWS_SECRET}"),
        ("aws-secret-key", "AWS_SECRET_ACCESS_KEY=" + fake.synthetic(41, "long", fake.BASE64)),
        ("github-token", "GITHUB_TOKEN=ghp_" + "x" * 36),
        ("github-token", "ghp_short"),
        ("stripe-secret-key", "sk_test_" + fake.synthetic(24, "stripe-test")),
        ("stripe-secret-key", "pk_live_" + fake.synthetic(24, "stripe-pub")),
        ("slack-token", "xoxb-" + "X" * 16),
        ("slack-token", "xoxb-short"),
        ("slack-token", "xoxq-" + fake.synthetic(24, "not-a-slack-prefix")),
        ("twilio-api-key", "SK" + "a" * 32),
        # Stripe format, not Twilio:
        ("twilio-api-key", "sk_test_" + fake.synthetic(24, "not-twilio")),
        # account SID, not secret:
        ("twilio-api-key", "AC" + fake.synthetic(32, "account-sid", fake.HEX)),
        ("google-api-key", "AIza" + "A" * 35),
        ("jwt", "eyJhbGciOi.eyJzdWIiOi.abcdefghijkl"),  # header is not valid base64 JSON
        ("private-key", "-----BEGIN PUBLIC KEY-----"),
        ("private-key", 'if line == "-----BEGIN ' + 'PRIVATE KEY-----":'),
        ("database-url", "postgres://user:password@db.example.com/app"),
        ("database-url", "postgres://user:${DB_PASS}@db.internal.test/app"),
        ("database-url", "postgres://user@db.internal.test/app"),
        ("database-url", "postgres://app:" + fake.db_password() + "@localhost:5432/dev"),
        ("generic-api-key", 'api_key = "your_api_key_here_please"'),
        ("generic-api-key", "api_key = os.environ.get('API_KEY')"),
        ("generic-api-key", "api_key = settings.services.stripe.apikey"),
        ("generic-api-key", "api_key = " + "a" * 24),
        ("generic-secret", "client_secret = os.getenv('CLIENT_SECRET')"),
        ("generic-secret", "secret_name = 'my-service-secret-name'"),
        ("generic-secret", "secret: ${{ secrets.DEPLOY_SECRET }}"),
        ("password-assignment", "password = os.environ['DB_PASSWORD']"),
        ("password-assignment", "password = request.form.password"),
        ("password-assignment", "self.password_hash = db_password"),
        ("password-assignment", "password: Optional[str] = None"),
        ("password-assignment", 'password = "changeme"'),
        ("password-assignment", 'password = "${DB_PASSWORD}"'),
        ("password-assignment", "password=short"),
        ("password-assignment", "password: _PasswordType | None = None,"),
        ("password-assignment", "password: SecretStringValue"),
        ("password-assignment", "password = getpassword"),
        ("authorization-token", "Authorization: Bearer <token>"),
        ("authorization-token", "Authorization: Bearer YOUR_API_TOKEN_HERE_1234"),
        ("authorization-token", 'auth = f"Bearer {token}"'),
    ],
)
def test_ignores_false_positives(rule_id, line):
    assert detect(rule_id, line) == []


def test_quoted_word_password_is_reported_at_lower_confidence_than_a_mixed_one():
    (plain,) = detect("password-assignment", QUOTED_WORD)
    (mixed,) = detect("password-assignment", QUOTED_MIXED)
    assert plain.confidence < mixed.confidence


def test_localhost_database_url_is_low_confidence():
    line = "postgres://app:" + fake.db_password() + "@localhost:5432/dev"
    (hit,) = RULES_BY_ID["database-url"].find(line, line.lower())
    assert hit.confidence < DEFAULT_MIN_CONFIDENCE


def test_private_key_header_followed_by_escaped_newline_is_high_confidence():
    header = fake.private_key_header()
    (embedded,) = detect("private-key", f'"{header}\\nMIIE"')
    (bare,) = detect("private-key", header)
    assert embedded.confidence == bare.confidence == 0.95


def test_keyword_prefilter_skips_unrelated_lines():
    rule = RULES_BY_ID["github-token"]
    line = "nothing interesting here"
    assert list(rule.find(line, line.lower())) == []


def test_severity_of_prefixed_credentials_is_high():
    for rule_id in (
        "aws-access-key",
        "github-token",
        "stripe-secret-key",
        "private-key",
        "slack-token",
        "twilio-api-key",
    ):
        assert RULES_BY_ID[rule_id].severity is Severity.HIGH


class TestMask:
    def test_hides_everything_by_default(self):
        assert mask("abcdef123456") == MASK

    def test_keeps_known_prefix_only(self):
        assert mask("AKIA" + fake.synthetic(16, "mask"), 4) == "AKIA" + MASK

    def test_length_of_secret_is_not_revealed(self):
        assert mask("a" * 8) == mask("a" * 80)

    def test_fully_visible_prefix_is_returned_unmasked(self):
        header = "-----BEGIN PRIVATE KEY-----"
        assert mask(header, 100) == header
