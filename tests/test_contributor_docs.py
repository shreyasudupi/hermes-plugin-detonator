"""Contributor docs and GitHub issue forms stay valid and link to files that exist."""

import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml")

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORMS = sorted((ROOT / ".github" / "ISSUE_TEMPLATE").glob("[0-9]*.yml"))
DOCS = [ROOT / "CONTRIBUTING.md", ROOT / "docs" / "QUICKSTART.md"]


def test_issue_forms_exist():
    names = {p.name for p in FORMS}
    assert {"1-bug.yml", "2-false-alarm.yml", "3-missed-behaviour.yml", "4-test-report.yml"} <= names


@pytest.mark.parametrize("path", FORMS, ids=lambda p: p.name)
def test_issue_form_is_valid(path):
    form = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert form["name"] and form["description"] and form["body"]
    ids = [item["id"] for item in form["body"] if "id" in item]
    assert len(ids) == len(set(ids)), "field ids must be unique"
    for item in form["body"]:
        attrs = item["attributes"]
        if item["type"] == "markdown":
            assert attrs["value"].strip()
            continue
        assert attrs["label"].strip()
        for option in attrs.get("options", []):
            # YAML turns bare Yes/No into booleans and splits flow lists on commas.
            label = option["label"] if isinstance(option, dict) else option
            assert isinstance(label, str) and label.strip(), (path.name, option)


def test_issue_config_points_security_reports_to_private_advisories():
    config = yaml.safe_load((ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8"))
    assert any(link["url"].endswith("/security/advisories/new") for link in config["contact_links"])


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_relative_links_point_to_real_files(doc):
    text = doc.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)#:]+)(?:#[^)]*)?\)", text):
        assert (doc.parent / target).exists(), f"{doc.name} links to missing {target}"
