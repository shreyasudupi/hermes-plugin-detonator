"""The README must name the current plugin.yaml version, at the top and first in the Versions list."""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_readme_version_matches_plugin_yaml():
    version = re.search(r'^version:\s*"?([0-9][^"\s]*)"?', (ROOT / "plugin.yaml").read_text(encoding="utf-8"), re.M).group(1)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"**Current version: v{version}**" in readme, f"README top line should say v{version}"
    versions = readme.split("## Versions", 1)[1]
    first = re.search(r"^- \*\*v([0-9][^*]*)\*\*", versions, re.M).group(1)
    assert first == version, f"first entry under Versions is v{first}, plugin.yaml says {version}"
