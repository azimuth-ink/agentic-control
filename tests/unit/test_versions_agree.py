"""The release version is stated in five places; they must agree (RELEASING.md)."""
import json
import re
from pathlib import Path

import agentic_control

ROOT = Path(__file__).resolve().parents[2]


def test_versions_agree():
    py = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
    cff = re.search(r"^version: (\S+)", (ROOT / "CITATION.cff").read_text(), re.M).group(1)
    zen = json.loads((ROOT / ".zenodo.json").read_text())["version"]
    chg = re.search(r"^## (\S+)", (ROOT / "CHANGELOG.md").read_text(), re.M).group(1)
    assert py == cff == zen == chg == agentic_control.__version__
