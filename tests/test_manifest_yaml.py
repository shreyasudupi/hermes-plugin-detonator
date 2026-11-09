"""plugin.yaml must parse inside Hermes, which ships ruamel.yaml but not PyYAML."""

import builtins
import pathlib

import pytest

from engine import runner

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_manifest_parses_without_pyyaml(monkeypatch):
    pytest.importorskip("ruamel.yaml")
    real_import = builtins.__import__

    def no_pyyaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("simulate Hermes env without PyYAML")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_pyyaml)
    data = runner.load_manifest(ROOT)
    assert data["name"] == "detonator"
    assert "detonate_plugin" in data["provides_tools"]
