import pytest

import synthetic as fake
from repo import write_tree


@pytest.fixture
def leaky_project(tmp_path):
    """A small web app with a few committed credentials and plenty of innocent code."""
    write_tree(
        tmp_path,
        {
            "README.md": "# Demo\n\nSet AWS_ACCESS_KEY_ID in your environment.\n",
            "src/app.py": (
                "import os\n\n"
                "DEBUG = True\n"
                'DB_URL = os.environ["DATABASE_URL"]\n'
                "PASSWORD_MIN_LENGTH = 12\n"
            ),
            "src/config.py": (
                f'AWS_ACCESS_KEY_ID = "{fake.aws_access_key()}"\n'
                f'STRIPE_KEY = "{fake.stripe_key()}"\n'
            ),
            "deploy/.env": f"SECRET_KEY={fake.generic_secret()}\n",
            "web/package-lock.json": '{"integrity": "sha512-' + fake.synthetic(60, "lock") + '"}\n',
            "web/index.js": "const api = '/v1/items';\n",
            "assets/logo.png": b"\x89PNG\r\n\x1a\n\x00\x00",
        },
    )
    return tmp_path


@pytest.fixture
def clean_project(tmp_path):
    write_tree(
        tmp_path,
        {
            "main.py": 'import os\n\nTOKEN = os.environ["TOKEN"]\nprint("hello")\n',
            "docs/notes.md": "Use AKIAIOSFODNN7EXAMPLE as the placeholder key.\n",
        },
    )
    return tmp_path
