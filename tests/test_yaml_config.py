"""Tests for service configuration infrastructure (YAML + TOML)."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from contextunity.core.config import (
    ServiceConfig,
    SharedConfig,
    load_config_file,
    load_service_config,
    read_service_file,
)
from pydantic import BaseModel, Field

# ── Helpers & fixtures ───────────────────────────────────────────────


class DemoModelsConfig(BaseModel):
    """Nested demo model for merge regression tests."""

    default_llm: str = "default-model"
    fallback_llms: list[str] = Field(default_factory=list)


class DemoRouterConfig(BaseModel):
    """Nested demo router section for merge regression tests."""

    port: int = 9000
    tenants: list[str] = Field(default_factory=list)


class DemoServiceConfig(ServiceConfig):
    """Minimal service config for testing."""

    demo_port: int = Field(default=9090)
    demo_name: str = Field(default="demo")
    demo_debug: bool = Field(default=False)
    models: DemoModelsConfig = Field(default_factory=DemoModelsConfig)
    router: DemoRouterConfig = Field(default_factory=DemoRouterConfig)


@pytest.fixture()
def yaml_dir(tmp_path: Path) -> Path:
    """Create a temp directory usable as config root."""
    return tmp_path


@pytest.fixture()
def yaml_file(yaml_dir: Path) -> Path:
    """Write a simple YAML config and return the path."""
    p = yaml_dir / "demo.yml"
    p.write_text(
        textwrap.dedent("""\
        log_level: DEBUG
        demo_port: 7070
        demo_name: from-yaml
        """),
        encoding="utf-8",
    )
    return p


@pytest.fixture()
def toml_file(yaml_dir: Path) -> Path:
    """Write a simple TOML config and return the path."""
    p = yaml_dir / "demo.toml"
    p.write_text(
        textwrap.dedent("""\
        log_level = "DEBUG"
        demo_port = 8080
        demo_name = "from-toml"
        """),
        encoding="utf-8",
    )
    return p


# ── ServiceConfig inheritance ────────────────────────────────────────


class TestServiceConfig:
    """Verify ServiceConfig is a proper SharedConfig subclass."""

    def test_inherits_shared_config(self) -> None:
        assert issubclass(ServiceConfig, SharedConfig)

    def test_extra_allowed(self) -> None:
        """ServiceConfig allows unknown fields (extra=ignore)."""
        cfg = ServiceConfig(unknown_field="ok")  # type: ignore[call-arg]
        assert isinstance(cfg, SharedConfig)

    def test_subclass_can_add_fields(self) -> None:
        cfg = DemoServiceConfig(demo_port=1234)
        assert cfg.demo_port == 1234
        # Inherited SharedConfig defaults
        assert cfg.brain_url == "localhost:50051"


# ── read_service_file ───────────────────────────────────────────────
# Note: code lives in config.loader, so mock paths target that module.

_LOADER = "contextunity.core.config.loader"


class TestReadServiceFile:
    """Test config file discovery chain (YAML + TOML).

    Resolution order:
      1. CU_{SERVICE}_CONFIG_FILE env   (explicit file)
      2. CU_CONFIG_DIR/{service}.yml    (explicit dir, overrides fallback)
      3. fallback_dirs/{service}.yml    (default: [CWD])
      4. /etc/contextunity/{service}.yml (system fallback)
    """

    def test_returns_empty_when_no_file(self) -> None:
        with patch(f"{_LOADER}.SYSTEM_CONFIG_DIR", Path("/nonexistent")):
            with patch.dict(os.environ, {}, clear=True):
                with patch(f"{_LOADER}.Path.cwd", return_value=Path("/nonexistent")):
                    assert read_service_file("demo") == {}

    def test_reads_system_yaml(self, yaml_file: Path) -> None:
        """System dir fallback picks up {service}.yml."""
        system_dir = yaml_file.parent
        with patch(f"{_LOADER}.SYSTEM_CONFIG_DIR", system_dir):
            with patch.dict(os.environ, {}, clear=True):
                with patch(f"{_LOADER}.Path.cwd", return_value=Path("/nonexistent")):
                    result = read_service_file("demo")
        assert result["log_level"] == "DEBUG"
        assert result["demo_port"] == 7070

    def test_reads_system_toml(self, toml_file: Path) -> None:
        system_dir = toml_file.parent
        with patch(f"{_LOADER}.SYSTEM_CONFIG_DIR", system_dir):
            with patch.dict(os.environ, {}, clear=True):
                with patch(f"{_LOADER}.Path.cwd", return_value=Path("/nonexistent")):
                    result = read_service_file("demo")
        assert result["demo_port"] == 8080
        assert result["demo_name"] == "from-toml"

    def test_yaml_has_priority_over_toml(self, yaml_file: Path, toml_file: Path) -> None:
        """When both YAML and TOML exist in the same dir, YAML wins."""
        system_dir = yaml_file.parent  # same dir for both
        with patch(f"{_LOADER}.SYSTEM_CONFIG_DIR", system_dir):
            with patch.dict(os.environ, {}, clear=True):
                with patch(f"{_LOADER}.Path.cwd", return_value=Path("/nonexistent")):
                    result = read_service_file("demo")
        assert result["demo_port"] == 7070  # from YAML, not 8080 from TOML

    def test_env_file_override(self, yaml_file: Path) -> None:
        """CU_{SERVICE}_CONFIG_FILE points to a specific file (highest priority)."""
        with patch(f"{_LOADER}.SYSTEM_CONFIG_DIR", Path("/nonexistent")):
            with patch.dict(os.environ, {"CU_DEMO_CONFIG_FILE": str(yaml_file)}, clear=True):
                result = read_service_file("demo")
        assert result["demo_name"] == "from-yaml"

    def test_cu_config_dir_override(self, yaml_dir: Path) -> None:
        """CU_CONFIG_DIR points to a directory containing {service}.yml."""
        cfg = yaml_dir / "demo.yml"
        cfg.write_text("demo_port: 3333\n", encoding="utf-8")

        with patch(f"{_LOADER}.SYSTEM_CONFIG_DIR", Path("/nonexistent")):
            env = {"CU_CONFIG_DIR": str(yaml_dir)}
            with patch.dict(os.environ, env, clear=True):
                with patch(f"{_LOADER}.Path.cwd", return_value=Path("/nonexistent")):
                    result = read_service_file("demo")
        assert result["demo_port"] == 3333

    def test_cwd_is_default_search_dir(self, yaml_dir: Path) -> None:
        """Services find {service}.yml directly in CWD (no .contextunity/ subdir)."""
        (yaml_dir / "demo.yml").write_text("demo_debug: true\n", encoding="utf-8")

        with patch(f"{_LOADER}.SYSTEM_CONFIG_DIR", Path("/nonexistent")):
            with patch.dict(os.environ, {}, clear=True):
                with patch(f"{_LOADER}.Path.cwd", return_value=yaml_dir):
                    result = read_service_file("demo")
        assert result["demo_debug"] is True

    def test_cwd_beats_system(self, yaml_dir: Path, tmp_path: Path) -> None:
        """CWD config takes priority over system /etc/."""
        system_dir = tmp_path / "system"
        system_dir.mkdir()
        (system_dir / "demo.yml").write_text("demo_port: 7070\n", encoding="utf-8")

        # CWD has demo.yml with different port
        (yaml_dir / "demo.yml").write_text("demo_port: 9999\n", encoding="utf-8")

        with patch(f"{_LOADER}.SYSTEM_CONFIG_DIR", system_dir):
            with patch.dict(os.environ, {}, clear=True):
                with patch(f"{_LOADER}.Path.cwd", return_value=yaml_dir):
                    result = read_service_file("demo")
        assert result["demo_port"] == 9999  # CWD wins

    def test_fallback_dirs_used_when_no_cu_config_dir(self, yaml_dir: Path) -> None:
        """CLI passes custom fallback_dirs (e.g. CWD/.contextunity, ~/.contextunity)."""
        cu_dir = yaml_dir / ".contextunity"
        cu_dir.mkdir()
        (cu_dir / "contextunity.yml").write_text("demo_port: 4444\n", encoding="utf-8")

        with patch(f"{_LOADER}.SYSTEM_CONFIG_DIR", Path("/nonexistent")):
            with patch.dict(os.environ, {}, clear=True):
                result = read_service_file("contextunity", fallback_dirs=[cu_dir])
        assert result["demo_port"] == 4444

    def test_cu_config_dir_overrides_fallback_dirs(self, yaml_dir: Path, tmp_path: Path) -> None:
        """CU_CONFIG_DIR takes priority over fallback_dirs."""
        # fallback dir has config
        fallback = tmp_path / "fallback"
        fallback.mkdir()
        (fallback / "demo.yml").write_text("demo_port: 1111\n", encoding="utf-8")

        # CU_CONFIG_DIR has config with different value
        override = tmp_path / "override"
        override.mkdir()
        (override / "demo.yml").write_text("demo_port: 2222\n", encoding="utf-8")

        with patch(f"{_LOADER}.SYSTEM_CONFIG_DIR", Path("/nonexistent")):
            env = {"CU_CONFIG_DIR": str(override)}
            with patch.dict(os.environ, env, clear=True):
                result = read_service_file("demo", fallback_dirs=[fallback])
        assert result["demo_port"] == 2222  # CU_CONFIG_DIR wins


# ── load_config_file ────────────────────────────────────────────────


class TestLoadConfigFile:
    """Test YAML/TOML parsing and security stripping."""

    def test_empty_yaml_returns_empty_dict(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.yml"
        p.write_text("", encoding="utf-8")
        assert load_config_file(p) == {}

    def test_non_dict_yaml_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "list.yml"
        p.write_text("- a\n- b\n", encoding="utf-8")
        with pytest.raises(Exception, match="Config file must be a JSON mapping"):
            load_config_file(p)

    def test_valid_yaml(self, tmp_path: Path) -> None:
        p = tmp_path / "ok.yml"
        p.write_text("key: value\nnum: 42\n", encoding="utf-8")
        assert load_config_file(p) == {"key": "value", "num": 42}

    def test_valid_toml(self, tmp_path: Path) -> None:
        p = tmp_path / "ok.toml"
        p.write_text('key = "value"\nnum = 42\n', encoding="utf-8")
        assert load_config_file(p) == {"key": "value", "num": 42}

    def test_unsupported_extension_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "config.json"
        p.write_text('{"key": "value"}', encoding="utf-8")
        with pytest.raises(Exception, match="Unsupported config file format"):
            load_config_file(p)

    def test_secret_keys_stripped(self, tmp_path: Path) -> None:
        """Secret-like keys are silently removed from config files."""
        p = tmp_path / "secrets.yml"
        p.write_text(
            textwrap.dedent("""\
            log_level: DEBUG
            password: should-be-stripped
            api_key: should-be-stripped
            openai:
              api_key: nested-should-be-stripped
              organization: safe-non-secret
            security:
              project_secret: nope
            demo_port: 1234
            """),
            encoding="utf-8",
        )
        result = load_config_file(p)
        assert result["log_level"] == "DEBUG"
        assert result["demo_port"] == 1234
        assert "password" not in result
        assert "api_key" not in result
        assert result["openai"] == {"organization": "safe-non-secret"}
        assert "security" not in result

    def test_secret_keys_stripped_toml(self, tmp_path: Path) -> None:
        """Secret stripping works for TOML too."""
        p = tmp_path / "secrets.toml"
        p.write_text(
            'log_level = "DEBUG"\npassword = "nope"\ndemo_port = 1234\n',
            encoding="utf-8",
        )
        result = load_config_file(p)
        assert "password" not in result
        assert result["demo_port"] == 1234


# ── load_service_config ──────────────────────────────────────────────

_FACTORY = "contextunity.core.config.factory"


class TestLoadServiceConfig:
    """Test the unified factory function."""

    @patch.dict(os.environ, {}, clear=True)
    def test_defaults_no_file(self) -> None:
        with (
            patch(f"{_FACTORY}.read_service_file", return_value={}),
            patch(f"{_FACTORY}.load_dotenv_chain"),
        ):
            cfg = load_service_config(DemoServiceConfig, "demo")
        assert cfg.demo_port == 9090
        assert cfg.demo_name == "demo"
        assert cfg.log_level == "INFO"

    @patch.dict(os.environ, {"LOG_LEVEL": "WARNING"}, clear=True)
    def test_env_overrides_defaults(self) -> None:
        with patch(f"{_FACTORY}.read_service_file", return_value={}):
            cfg = load_service_config(DemoServiceConfig, "demo")
        assert cfg.log_level == "WARNING"

    @patch.dict(os.environ, {"LOG_LEVEL": "WARNING"}, clear=True)
    def test_env_overrides_file(self) -> None:
        file_data = {"log_level": "ERROR", "demo_port": 5555}
        with patch(f"{_FACTORY}.read_service_file", return_value=file_data):
            cfg = load_service_config(DemoServiceConfig, "demo")
        assert cfg.log_level == "WARNING"
        assert cfg.demo_port == 5555

    @patch.dict(os.environ, {}, clear=True)
    def test_extra_env_merged(self) -> None:
        extra = {"demo_name": "from-extra"}
        with patch(f"{_FACTORY}.read_service_file", return_value={}):
            cfg = load_service_config(DemoServiceConfig, "demo", extra_env=extra)
        assert cfg.demo_name == "from-extra"

    @patch.dict(os.environ, {}, clear=True)
    def test_explicit_config_path(self, tmp_path: Path) -> None:
        config_path = tmp_path / "explicit.yml"
        config_path.write_text("demo_name: from-explicit\n", encoding="utf-8")

        cfg = load_service_config(DemoServiceConfig, "demo", config_path=config_path)

        assert cfg.demo_name == "from-explicit"

    @patch.dict(os.environ, {}, clear=True)
    def test_extra_env_wins_over_file(self) -> None:
        extra = {"demo_name": "from-extra"}
        file_data = {"demo_name": "from-file"}
        with patch(f"{_FACTORY}.read_service_file", return_value=file_data):
            cfg = load_service_config(DemoServiceConfig, "demo", extra_env=extra)
        assert cfg.demo_name == "from-extra"

    @patch.dict(os.environ, {"CU_DEMO_DEFAULT_LLM": "env-model"}, clear=True)
    def test_nested_overrides_deep_merge_without_wiping_siblings(self) -> None:
        """Nested env/extra overrides preserve sibling keys in the same section."""
        extra = {"models": {"fallback_llms": ["a", "b"]}}
        with patch(f"{_FACTORY}.read_service_file", return_value={}):
            cfg = load_service_config(
                DemoServiceConfig,
                "demo",
                env_mappings={"CU_DEMO_DEFAULT_LLM": "models.default_llm"},
                extra_env=extra,
            )
        assert cfg.models.default_llm == "env-model"
        assert cfg.models.fallback_llms == ["a", "b"]

    @patch.dict(os.environ, {"CU_DEMO_ROUTER_PORT": "1234"}, clear=True)
    def test_dotted_extra_env_deep_merge_without_wiping_siblings(self) -> None:
        """Dotted computed overrides do not replace the whole parent section."""
        extra = {"router.tenants": ["tenant-a", "tenant-b"]}
        with patch(f"{_FACTORY}.read_service_file", return_value={}):
            cfg = load_service_config(
                DemoServiceConfig,
                "demo",
                env_mappings={"CU_DEMO_ROUTER_PORT": "router.port"},
                extra_env=extra,
            )
        assert cfg.router.port == 1234
        assert cfg.router.tenants == ["tenant-a", "tenant-b"]

    @patch.dict(os.environ, {}, clear=True)
    def test_extra_env_nested_dict_without_existing_parent(self) -> None:
        """Nested extra_env must apply even when the parent section is absent."""
        extra = {"models": {"fallback_llms": ["a", "b"]}}
        with patch(f"{_FACTORY}.read_service_file", return_value={}):
            cfg = load_service_config(DemoServiceConfig, "demo", extra_env=extra)
        assert cfg.models.fallback_llms == ["a", "b"]


pytestmark = pytest.mark.unit
