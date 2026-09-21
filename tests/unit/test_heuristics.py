import pytest

from envguard.heuristics import char_classes, is_placeholder, looks_like_reference, shannon_entropy


def test_entropy_of_repeated_character_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_grows_with_variety():
    assert shannon_entropy("abcdefgh") == pytest.approx(3.0)
    assert shannon_entropy("aabbccdd") < shannon_entropy("abcdefgh")


@pytest.mark.parametrize(
    "value",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "your_api_key_here",
        "changeme",
        "Password",
        "${DB_PASSWORD}",
        "<token>",
        "xxxxxxxxxxxxxxxx",
        "abababab",
        "%(password)s",
        "REDACTED-VALUE",
    ],
)
def test_placeholders(value):
    assert is_placeholder(value)


@pytest.mark.parametrize("value", ["Zk3v9QpLw2XrT7mB", "correct-horse-battery", "hunter2hunter2"])
def test_real_looking_values_are_not_placeholders(value):
    assert not is_placeholder(value)


@pytest.mark.parametrize(
    "value", ["self.password", "config.db.password", "db_password", "user_input_1"]
)
def test_code_references(value):
    assert looks_like_reference(value)


@pytest.mark.parametrize("value", ["hunter2hunter2", "Zk3v9QpLw2XrT7mB", "abc.def-ghi"])
def test_non_references(value):
    assert not looks_like_reference(value)


def test_char_classes():
    assert char_classes("abc") == 1
    assert char_classes("abC1") == 3
    assert char_classes("aB3!") == 4
