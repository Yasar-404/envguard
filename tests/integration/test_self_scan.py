from pathlib import Path

import pytest

from envguard.config import Config
from envguard.scanner import scan_tree

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(not (ROOT / "src" / "envguard").is_dir(), reason="not a source checkout")
def test_repository_scans_clean():
    result = scan_tree(ROOT, Config())
    locations = [f"{f.file}:{f.line} {f.rule_id}" for f in result.findings]
    assert locations == []
    assert result.files_scanned > 20
