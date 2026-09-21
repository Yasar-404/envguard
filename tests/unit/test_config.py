import pytest

from envguard.config import CONFIG_FILENAME, Config, ConfigError, find_config, load_config
from envguard.models import Severity


def write_config(tmp_path, text):
    path = tmp_path / CONFIG_FILENAME
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults():
    config = Config()
    assert config.min_severity is Severity.LOW
    assert config.min_confidence == 0.5
    assert config.max_file_size == 1024 * 1024


def test_loads_all_options(tmp_path):
    path = write_config(
        tmp_path,
        """
exclude = ["docs/", "*.svg"]
disable_rules = ["jwt", "generic-secret"]
min_severity = "medium"
min_confidence = 0.7
max_file_size_kb = 256
""",
    )
    config = load_config(path)
    assert config.exclude == ("docs/", "*.svg")
    assert config.disable_rules == {"jwt", "generic-secret"}
    assert config.min_severity is Severity.MEDIUM
    assert config.min_confidence == 0.7
    assert config.max_file_size == 256 * 1024


def test_empty_file_gives_defaults(tmp_path):
    assert load_config(write_config(tmp_path, "")) == Config()


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("disable_rule = []", "unknown option"),
        ('disable_rules = ["no-such-rule"]', "unknown rule id"),
        ('min_severity = "critical"', "min_severity"),
        ("min_confidence = 1.5", "min_confidence"),
        ('min_confidence = "high"', "min_confidence"),
        ("max_file_size_kb = 0", "max_file_size_kb"),
        ('exclude = "docs"', "exclude must be a list"),
        ("exclude = [1, 2]", "exclude must be a list"),
        ("exclude = [", "invalid TOML"),
    ],
)
def test_invalid_config_is_rejected_with_a_clear_message(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load_config(write_config(tmp_path, text))


def test_missing_config_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "nope.toml")


def test_find_config_searches_parents_and_stops_at_repository_root(tmp_path):
    nested = tmp_path / "repo" / "src" / "pkg"
    nested.mkdir(parents=True)
    write_config(tmp_path, "")
    assert find_config(nested) == tmp_path / CONFIG_FILENAME

    (tmp_path / "repo" / ".git").mkdir()
    assert find_config(nested) is None

    repo_config = write_config(tmp_path / "repo", "")
    assert find_config(nested) == repo_config
