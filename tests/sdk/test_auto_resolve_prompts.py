"""Tests for _auto_resolve_prompt_refs — auto-importing prompts from project code."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml
from contextunity.core.sdk.bootstrap.manifest import (
    _auto_resolve_prompt_refs,
    _file_to_module_path,
    _resolve_yaml_prompt,
)


def _create_python_module(tmp_path: Path, pkg_name: str, content: str) -> None:
    """Create a Python package with a prompts module under src/<pkg>/."""
    src = tmp_path / "src" / pkg_name
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "prompts.py").write_text(content)


@pytest.fixture(autouse=True)
def _cleanup_sys_modules():
    """Remove test modules from sys.modules after each test."""
    before = set(sys.modules.keys())
    yield
    for key in list(sys.modules.keys()):
        if key not in before:
            del sys.modules[key]


class TestAutoResolvePromptRefs:
    """Test automatic prompt resolution from manifest prompt_ref values."""

    def test_python_module_ref(self, tmp_path):
        """Resolves 'src/pkg_a/prompts.py::MY_PROMPT' by importing module."""
        _create_python_module(tmp_path, "pkg_a", 'MY_PROMPT = "You are a helpful assistant."\n')

        manifest_path = str(tmp_path / "contextunity.project.yaml")
        manifest_dict = {
            "router": {
                "graph": {
                    "nodes": [
                        {
                            "name": "planner",
                            "type": "llm",
                            "prompt_ref": "src/pkg_a/prompts.py::MY_PROMPT",
                        }
                    ]
                }
            }
        }

        result = _auto_resolve_prompt_refs(manifest_dict, manifest_path)
        assert "src/pkg_a/prompts.py::MY_PROMPT" in result
        assert result["src/pkg_a/prompts.py::MY_PROMPT"] == "You are a helpful assistant."

    def test_yaml_prompt_ref(self, tmp_path):
        """Resolves 'tech_reporter' by reading prompts/agents/tech_reporter.yaml."""
        prompts_dir = tmp_path / "prompts" / "agents"
        prompts_dir.mkdir(parents=True)
        (prompts_dir / "tech_reporter.yaml").write_text(yaml.dump({"system_prompt": "You are a tech reporter."}))

        manifest_path = str(tmp_path / "contextunity.project.yaml")
        manifest_dict = {
            "router": {
                "graph": {
                    "nodes": [
                        {
                            "name": "tech_reporter",
                            "type": "llm",
                            "prompt_ref": "tech_reporter",
                        }
                    ]
                }
            }
        }

        result = _auto_resolve_prompt_refs(manifest_dict, manifest_path)
        assert result.get("tech_reporter") == "You are a tech reporter."

    def test_empty_when_no_refs(self):
        """Returns empty dict when manifest has no prompt_ref values."""
        manifest_dict = {"router": {"graph": {"nodes": [{"name": "tool_exec", "type": "tool"}]}}}
        result = _auto_resolve_prompt_refs(manifest_dict, "/fake/manifest.yaml")
        assert result == {}

    def test_empty_when_no_router(self):
        """Returns empty dict when manifest has no router section."""
        result = _auto_resolve_prompt_refs({"project": {"id": "test"}}, "/fake/manifest.yaml")
        assert result == {}

    def test_tool_config_ref(self, tmp_path):
        """Resolves tool config _ref values too."""
        _create_python_module(tmp_path, "pkg_b", 'DB_SCHEMA = "CREATE TABLE foo ..."\n')

        manifest_path = str(tmp_path / "contextunity.project.yaml")
        manifest_dict = {
            "router": {
                "graph": {"nodes": []},
                "tools": [
                    {
                        "name": "sql_tool",
                        "type": "sql",
                        "config": {
                            "schema_description_ref": "src/pkg_b/prompts.py::DB_SCHEMA",
                        },
                    }
                ],
            }
        }

        result = _auto_resolve_prompt_refs(manifest_dict, manifest_path)
        assert result.get("src/pkg_b/prompts.py::DB_SCHEMA") == "CREATE TABLE foo ..."

    def test_variants_ref(self, tmp_path):
        """Resolves prompt_variants_ref (dict of sub-prompts)."""
        _create_python_module(
            tmp_path,
            "pkg_c",
            'SUBS = {"report": "Make a report.", "chart": "Make a chart."}\n',
        )

        manifest_path = str(tmp_path / "contextunity.project.yaml")
        manifest_dict = {
            "router": {
                "graph": {
                    "nodes": [
                        {
                            "name": "viz",
                            "type": "llm",
                            "prompt_variants_ref": "src/pkg_c/prompts.py::SUBS",
                        }
                    ]
                }
            }
        }

        result = _auto_resolve_prompt_refs(manifest_dict, manifest_path)
        assert result["src/pkg_c/prompts.py::SUBS"] == {
            "report": "Make a report.",
            "chart": "Make a chart.",
        }


class TestFileToModulePath:
    def test_src_relative(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        result = _file_to_module_path(src / "chat" / "prompts.py", tmp_path)
        assert result == "chat.prompts"

    def test_root_relative(self, tmp_path):
        result = _file_to_module_path(tmp_path / "mymod.py", tmp_path)
        assert result == "mymod"

    def test_unrelated_path(self, tmp_path):
        result = _file_to_module_path(Path("/completely/other/path.py"), tmp_path)
        assert result is None


class TestResolveYamlPrompt:
    def test_agents_subdir(self, tmp_path):
        d = tmp_path / "prompts" / "agents"
        d.mkdir(parents=True)
        (d / "reporter.yaml").write_text(yaml.dump({"system_prompt": "Report!"}))
        assert _resolve_yaml_prompt("reporter", tmp_path) == "Report!"

    def test_prompts_root(self, tmp_path):
        d = tmp_path / "prompts"
        d.mkdir()
        (d / "helper.yaml").write_text(yaml.dump({"base_prompt": "Help!"}))
        assert _resolve_yaml_prompt("helper", tmp_path) == "Help!"

    def test_not_found(self, tmp_path):
        assert _resolve_yaml_prompt("nonexistent", tmp_path) is None

    def test_src_subpackage(self, tmp_path):
        """Finds prompts under src/<pkg>/prompts/agents/."""
        d = tmp_path / "src" / "myapp" / "prompts" / "agents"
        d.mkdir(parents=True)
        (d / "bot.yaml").write_text(yaml.dump({"system_prompt": "I am bot."}))
        assert _resolve_yaml_prompt("bot", tmp_path) == "I am bot."
