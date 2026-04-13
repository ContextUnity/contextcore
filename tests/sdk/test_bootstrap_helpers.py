"""Tests for contextunity.core.sdk.bootstrap.helpers — bootstrap_django, bootstrap_standalone."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml
from contextunity.core.sdk.bootstrap.helpers import (
    _build_prompt_map,
    _find_manifest_path,
)

# ── _find_manifest_path ──


class TestFindManifestPath:
    def test_explicit_hint_wins(self):
        import contextunity.core.config as core_config

        core_config._core_config = None
        result = _find_manifest_path("/some/explicit/path.yaml")
        assert result == "/some/explicit/path.yaml"

    def test_env_var_second(self, monkeypatch):
        import contextunity.core.config as core_config

        core_config._core_config = None
        monkeypatch.setenv("CU_MANIFEST_PATH", "/env/manifest.yaml")
        result = _find_manifest_path()
        assert result == "/env/manifest.yaml"

    def test_walks_up_cwd(self, tmp_path, monkeypatch):
        import contextunity.core.config as core_config

        core_config._core_config = None
        manifest = tmp_path / "contextunity.project.yaml"
        manifest.write_text("project:\n  id: test\n")

        subdir = tmp_path / "src" / "app"
        subdir.mkdir(parents=True)
        monkeypatch.chdir(subdir)
        monkeypatch.delenv("CU_MANIFEST_PATH", raising=False)

        result = _find_manifest_path()
        assert result == str(manifest)

    def test_default_fallback(self, tmp_path, monkeypatch):
        import contextunity.core.config as core_config

        core_config._core_config = None
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("CU_MANIFEST_PATH", raising=False)
        result = _find_manifest_path()
        assert result == "contextunity.project.yaml"


# ── _build_prompt_map ──


class TestBuildPromptMap:
    def _write_manifest(self, path: Path, manifest: dict):
        path.write_text(yaml.dump(manifest))

    def test_none_prompts(self, tmp_path):
        manifest = tmp_path / "contextunity.project.yaml"
        self._write_manifest(manifest, {"project": {"id": "test"}})
        result = _build_prompt_map(None, str(manifest))
        assert result is None

    def test_full_ref_passthrough(self, tmp_path):
        """Keys with '::' are treated as full refs — returned as-is."""
        manifest = tmp_path / "contextunity.project.yaml"
        self._write_manifest(manifest, {"project": {"id": "test"}})

        prompts = {
            "src/chat/prompts.py::PLANNER_PROMPT": "You are a planner.",
            "src/chat/prompts.py::DB_SCHEMA": "CREATE TABLE ...",
        }
        result = _build_prompt_map(prompts, str(manifest))
        assert result is prompts

    def test_short_key_resolution(self, tmp_path):
        """Short keys are mapped to prompt_ref values from manifest nodes."""
        manifest = tmp_path / "contextunity.project.yaml"
        self._write_manifest(
            manifest,
            {
                "project": {"id": "test"},
                "router": {
                    "graph": {
                        "id": "test",
                        "template": "sql_analytics",
                        "nodes": [
                            {
                                "name": "planner",
                                "type": "llm",
                                "model": "openai/gpt-5-mini",
                                "prompt_ref": "src/prompts.py::PLAN",
                            },
                            {
                                "name": "visualizer",
                                "type": "llm",
                                "model": "openai/gpt-5-mini",
                                "prompt_ref": "src/prompts.py::VIS",
                                "prompt_variants_ref": "src/prompts.py::VIS_SUBS",
                            },
                        ],
                    },
                    "tools": [
                        {
                            "name": "test_sql",
                            "type": "sql",
                            "execution": "federated",
                            "config": {
                                "schema_description_ref": "src/prompts.py::SCHEMA",
                            },
                        }
                    ],
                },
            },
        )

        prompts = {
            "planner": "You are a planner.",
            "visualizer": "Make charts.",
            "visualizer_sub_prompts": {"chart": "Chart sub-prompt"},
            "schema_description": "CREATE TABLE records ...",
        }
        result = _build_prompt_map(prompts, str(manifest))

        assert result is not None
        assert result["src/prompts.py::PLAN"] == "You are a planner."
        assert result["src/prompts.py::VIS"] == "Make charts."
        assert result["src/prompts.py::VIS_SUBS"] == {"chart": "Chart sub-prompt"}
        assert result["src/prompts.py::SCHEMA"] == "CREATE TABLE records ..."

    def test_missing_manifest_returns_original(self, tmp_path):
        """If manifest can't be read, return original prompts dict."""
        result = _build_prompt_map(
            {"planner": "text"},
            str(tmp_path / "nonexistent.yaml"),
        )
        assert result == {"planner": "text"}


# ── bootstrap_django ──

# helpers.py does `_bootstrap_api.register_and_start(...)` where _bootstrap_api
# is imported from `.api`. We patch the function on that module object.
_PATCH_TARGET = "contextunity.core.sdk.bootstrap.helpers._bootstrap_api.register_and_start"


# ── bootstrap_standalone ──


class TestBootstrapStandalone:
    def test_runs_once(self, monkeypatch, tmp_path):
        """Double-checked locking should ensure single execution."""
        import contextunity.core.sdk.bootstrap.helpers as helpers_mod

        helpers_mod._BOOTSTRAPPED = False
        monkeypatch.setenv("CU_MANIFEST_PATH", str(tmp_path / "m.yaml"))

        with patch(_PATCH_TARGET) as mock_reg:
            helpers_mod.bootstrap_standalone()
            helpers_mod.bootstrap_standalone()  # second call should be no-op
            mock_reg.assert_called_once()

        helpers_mod._BOOTSTRAPPED = False
