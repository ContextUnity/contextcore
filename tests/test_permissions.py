"""Tests for permissions registry and identity scoping."""

from __future__ import annotations

import pytest
from contextunity.core import (
    DEFAULT_TOOL_POLICIES,
    NAMESPACE_PROFILES,
    PROJECT_PROFILES,
    ContextToken,
    Permissions,
    TokenBuilder,
    ToolPolicy,
    ToolRisk,
    ToolScope,
    UserNamespace,
    check_tool_scope,
    expand_permissions,
    extract_tool_names,
    has_graph_access,
    has_registration_access,
    has_tool_access,
    has_tool_scope_access,
)


class TestPermissions:
    """Tests for Permissions constants."""

    def test_permission_format(self) -> None:
        """All string-constant permissions follow domain:action format."""
        for attr in dir(Permissions):
            if attr.startswith("_"):
                continue
            value = getattr(Permissions, attr)
            if callable(value):
                continue  # Skip builders: tool(), graph(), service()
            assert ":" in value, f"{attr}={value} missing ':'"
            domain, action = value.split(":", 1)
            assert domain, f"{attr} has empty domain"
            assert action, f"{attr} has empty action"

    def test_unique_permissions(self) -> None:
        """All permission values are unique."""
        values = [
            getattr(Permissions, attr)
            for attr in dir(Permissions)
            if not attr.startswith("_") and not callable(getattr(Permissions, attr))
        ]
        assert len(values) == len(set(values)), "Duplicate permission values found"


class TestUserNamespace:
    """Tests for UserNamespace constants."""

    def test_all_contains_all_namespaces(self) -> None:
        """UserNamespace.ALL includes all defined namespaces."""
        for attr in ("DEFAULT", "FREE", "PRO", "ADMIN", "SYSTEM"):
            value = getattr(UserNamespace, attr)
            assert value in UserNamespace.ALL, f"{attr}={value} not in ALL"


class TestExpandPermissions:
    """Tests for permission inheritance expansion."""

    @pytest.mark.parametrize(
        ("input_perm", "expected_children"),
        [
            (
                Permissions.ADMIN_ALL,
                [
                    Permissions.ADMIN_READ,
                    Permissions.ADMIN_WRITE,
                    Permissions.ADMIN_TRACE,
                    Permissions.BRAIN_READ,
                    Permissions.BRAIN_WRITE,
                    Permissions.MEMORY_READ,
                    Permissions.MEMORY_WRITE,
                    Permissions.TRACE_READ,
                    Permissions.TRACE_WRITE,
                ],
            ),
            (Permissions.MEMORY_WRITE, [Permissions.MEMORY_READ]),
            (Permissions.BRAIN_WRITE, [Permissions.BRAIN_READ]),
            (Permissions.ADMIN_TRACE, [Permissions.TRACE_READ]),
            (
                Permissions.GRAPH_DISPATCHER,
                [
                    Permissions.GRAPH_RAG,
                    Permissions.GRAPH_COMMERCE,
                    Permissions.GRAPH_NEWS,
                    Permissions.GRAPH_MEDICAL,
                ],
            ),
        ],
        ids=["admin-all", "memory-write", "brain-write", "admin-trace", "graph-dispatcher"],
    )
    def test_inheritance_expansion(self, input_perm, expected_children) -> None:
        """Parent permission expands to include all children."""
        result = expand_permissions((input_perm,))
        assert input_perm in result
        for child in expected_children:
            assert child in result, f"{child} not found in expansion of {input_perm}"

    def test_no_expansion_for_leaf(self) -> None:
        """Leaf permissions don't expand."""
        result = expand_permissions((Permissions.BRAIN_READ,))
        assert result == (Permissions.BRAIN_READ,)

    def test_deduplication(self) -> None:
        """Duplicates in input are deduplicated."""
        result = expand_permissions((Permissions.BRAIN_READ, Permissions.BRAIN_READ))
        assert result.count(Permissions.BRAIN_READ) == 1

    def test_empty_input(self) -> None:
        """Empty input returns empty tuple."""
        assert expand_permissions(()) == ()


class TestNamespaceProfiles:
    """Tests for NAMESPACE_PROFILES mapping.

    Score 3: +2 behavior (permission escalation prevention), +1 documents contract.
    """

    def test_all_namespaces_have_profiles(self) -> None:
        """Every UserNamespace has a corresponding profile."""
        for ns in UserNamespace.ALL:
            assert ns in NAMESPACE_PROFILES, f"Missing profile for namespace: {ns}"

    @pytest.mark.parametrize(
        ("namespace", "must_have", "must_not_have"),
        [
            (
                UserNamespace.FREE,
                {Permissions.GRAPH_RAG, Permissions.BRAIN_READ},
                {Permissions.MEMORY_WRITE, Permissions.TRACE_WRITE},
            ),
            (UserNamespace.PRO, {Permissions.MEMORY_READ, Permissions.MEMORY_WRITE, Permissions.TRACE_WRITE}, set()),
            (UserNamespace.ADMIN, {Permissions.ADMIN_ALL}, set()),
        ],
        ids=["free-minimal", "pro-memory", "admin-all"],
    )
    def test_profile_permissions(self, namespace, must_have, must_not_have) -> None:
        """Namespace profiles enforce correct permission boundaries."""
        perms = NAMESPACE_PROFILES[namespace]
        for p in must_have:
            assert p in perms, f"{namespace} missing {p}"
        for p in must_not_have:
            assert p not in perms, f"{namespace} should not have {p}"


class TestProjectProfiles:
    """Tests for PROJECT_PROFILES.

    Score 2: +1 documents contract, +1 fast. Kept for profile registration validation.
    """

    @pytest.mark.parametrize("name", ["rag_readonly", "rag_full", "commerce", "medical", "admin"])
    def test_known_profiles(self, name) -> None:
        assert name in PROJECT_PROFILES


class TestTokenIdentityScoping:
    """Tests for user_id, agent_id, user_namespace on ContextToken."""

    def test_default_identity(self) -> None:
        """Token has default identity values."""
        token = ContextToken(token_id="test")
        assert token.user_id is None
        assert token.agent_id is None
        assert token.user_namespace == "default"

    def test_token_with_identity(self) -> None:
        """Token preserves identity fields."""
        token = ContextToken(
            token_id="test",
            permissions=(Permissions.BRAIN_READ,),
            user_id="dr_ivanov",
            agent_id="dispatcher",
            user_namespace="pro",
        )
        assert token.user_id == "dr_ivanov"
        assert token.agent_id == "dispatcher"
        assert token.user_namespace == "pro"

    def test_mint_root_with_identity(self) -> None:
        """TokenBuilder.mint_root includes identity fields."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=[Permissions.BRAIN_READ],
            ttl_s=300,
            user_id="dr_ivanov",
            agent_id="dispatcher",
            user_namespace="pro",
            allowed_tenants=["tenant_a"],
        )
        assert token.user_id == "dr_ivanov"
        assert token.agent_id == "dispatcher"
        assert token.user_namespace == "pro"
        assert token.allowed_tenants == ("tenant_a",)

    def test_attenuate_propagates_user_id(self) -> None:
        """Attenuation preserves user_id and user_namespace."""
        builder = TokenBuilder()
        parent = builder.mint_root(
            user_ctx={},
            permissions=[Permissions.BRAIN_READ, Permissions.MEMORY_WRITE],
            ttl_s=300,
            user_id="dr_ivanov",
            agent_id="dispatcher",
            user_namespace="pro",
            allowed_tenants=["tenant_a"],
        )
        child = builder.attenuate(
            parent,
            permissions=[Permissions.BRAIN_READ],
            agent_id="rag_agent",
        )
        # user_id and user_namespace inherited
        assert child.user_id == "dr_ivanov"
        assert child.user_namespace == "pro"
        assert child.allowed_tenants == ("tenant_a",)
        # agent_id changed
        assert child.agent_id == "rag_agent"
        # permissions attenuated
        assert child.has_permission(Permissions.BRAIN_READ)
        assert not child.has_permission(Permissions.MEMORY_WRITE)

    def test_attenuate_keeps_agent_id_if_not_overridden(self) -> None:
        """Attenuation keeps parent agent_id when not specified."""
        builder = TokenBuilder()
        parent = builder.mint_root(
            user_ctx={},
            permissions=[Permissions.BRAIN_READ],
            ttl_s=300,
            agent_id="dispatcher",
        )
        child = builder.attenuate(parent, ttl_s=30)
        assert child.agent_id == "dispatcher"

    def test_system_token_no_user(self) -> None:
        """System token has no user_id."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=list(NAMESPACE_PROFILES[UserNamespace.SYSTEM]),
            ttl_s=300,
            user_id=None,
            agent_id="gardener",
            user_namespace="system",
            allowed_tenants=["tenant_b"],
        )
        assert token.user_id is None
        assert token.agent_id == "gardener"
        assert token.user_namespace == "system"


class TestTokenIdentitySerialization:
    """Tests for identity fields in token serialization roundtrip."""

    def test_roundtrip_with_identity(self) -> None:
        """Token with identity fields survives serialization roundtrip."""
        from contextunity.core.signing import HmacBackend
        from contextunity.core.token_utils import parse_token_string, serialize_token

        backend = HmacBackend("test_proj", "test_secret")
        token = ContextToken(
            token_id="test_roundtrip",
            permissions=(Permissions.BRAIN_READ, Permissions.MEMORY_WRITE),
            allowed_tenants=("tenant_a",),
            exp_unix=9999999999.0,
            user_id="dr_ivanov",
            agent_id="dispatcher",
            user_namespace="pro",
        )
        serialized = serialize_token(token, backend=backend)
        parsed = parse_token_string(serialized)

        assert parsed is not None
        assert parsed.token_id == "test_roundtrip"
        assert parsed.user_id == "dr_ivanov"
        assert parsed.agent_id == "dispatcher"
        assert parsed.user_namespace == "pro"

    def test_roundtrip_default_namespace_and_backward_compat(self) -> None:
        """Default namespace omitted from wire; restores correctly (also covers old tokens)."""
        from contextunity.core.signing import HmacBackend
        from contextunity.core.token_utils import parse_token_string, serialize_token

        backend = HmacBackend("test_proj", "test_secret")
        token = ContextToken(
            token_id="minimal",
            permissions=(Permissions.BRAIN_READ,),
            exp_unix=9999999999.0,
        )
        serialized = serialize_token(token, backend=backend)
        assert "user_namespace" not in serialized

        parsed = parse_token_string(serialized)
        assert parsed is not None
        assert parsed.user_namespace == "default"
        assert parsed.user_id is None
        assert parsed.agent_id is None


class TestPermissionBuilders:
    """Tests for Permissions.tool(), .graph(), .service() builders."""

    @pytest.mark.parametrize(
        ("builder_call", "expected"),
        [
            (lambda: Permissions.tool("brain_search"), "tool:brain_search"),
            (lambda: Permissions.tool("sql"), Permissions.TOOL_SQL),
            (lambda: Permissions.graph("rag"), Permissions.GRAPH_RAG),
            (lambda: Permissions.graph("commerce"), Permissions.GRAPH_COMMERCE),
            (lambda: Permissions.service("brain", "read"), Permissions.BRAIN_READ),
            (lambda: Permissions.service("router", "execute"), Permissions.ROUTER_EXECUTE),
        ],
        ids=["tool-custom", "tool-sql", "graph-rag", "graph-commerce", "svc-brain-read", "svc-router-exec"],
    )
    def test_builder_produces_correct_string(self, builder_call, expected) -> None:
        """Builders produce domain:name format matching constants."""
        assert builder_call() == expected

    def test_builder_in_mint_root(self) -> None:
        """Builders work with TokenBuilder.mint_root()."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=[
                Permissions.tool("brain_search"),
                Permissions.graph("rag_retrieval"),
            ],
            ttl_s=300,
        )
        assert token.has_permission("tool:brain_search")
        assert token.has_permission("graph:rag_retrieval")
        assert not token.has_permission("tool:sql_execute")


class TestHasToolAccess:
    """Tests for has_tool_access() helper."""

    @pytest.mark.parametrize(
        ("perms", "tool_name", "expected"),
        [
            ((Permissions.tool("brain_search"), Permissions.tool("shield_scan")), "brain_search", True),
            ((Permissions.tool("brain_search"), Permissions.tool("shield_scan")), "shield_scan", True),
            ((Permissions.tool("brain_search"), Permissions.tool("shield_scan")), "sql_execute", False),
            ((Permissions.TOOL_ALL,), "anything_at_all", True),
            ((Permissions.ADMIN_ALL,), "anything", True),
            ((Permissions.BRAIN_READ, Permissions.MEMORY_WRITE), "brain_search", False),
            ((), "brain_search", False),
        ],
        ids=["exact-hit", "exact-hit-2", "exact-miss", "wildcard", "admin-all", "no-tool-perms", "empty"],
    )
    def test_access_matrix(self, perms, tool_name, expected) -> None:
        assert has_tool_access(perms, tool_name) is expected


class TestHasGraphAccess:
    """Tests for has_graph_access() helper."""

    @pytest.mark.parametrize(
        ("perms", "graph_name", "expected"),
        [
            ((Permissions.graph("rag_retrieval"),), "rag_retrieval", True),
            ((Permissions.graph("rag_retrieval"),), "commerce_search", False),
            ((Permissions.GRAPH_ALL,), "any_custom_graph", True),
            ((Permissions.GRAPH_DISPATCHER,), "rag_retrieval", True),
            ((Permissions.ADMIN_ALL,), "any_graph", True),
            ((Permissions.BRAIN_READ,), "rag_retrieval", False),
        ],
        ids=["exact-hit", "exact-miss", "wildcard", "dispatcher", "admin-all", "no-graph-perms"],
    )
    def test_access_matrix(self, perms, graph_name, expected) -> None:
        assert has_graph_access(perms, graph_name) is expected


class TestExtractToolNames:
    """Tests for extract_tool_names() helper."""

    @pytest.mark.parametrize(
        ("perms", "expected"),
        [
            (("tool:brain_search", "tool:shield_scan", "brain:read"), frozenset({"brain_search", "shield_scan"})),
            ((Permissions.TOOL_ALL, "brain:read"), frozenset({"*"})),
            ((Permissions.ADMIN_ALL,), frozenset({"*"})),
            ((Permissions.BRAIN_READ, Permissions.MEMORY_WRITE), frozenset()),
            (
                (Permissions.tool("recall_facts"), Permissions.tool("remember_episode"), Permissions.BRAIN_READ),
                frozenset({"recall_facts", "remember_episode"}),
            ),
        ],
        ids=["concrete-names", "wildcard", "admin-all", "no-tools", "builder-produced"],
    )
    def test_extraction(self, perms, expected) -> None:
        assert extract_tool_names(perms) == expected


class TestToolScopeConstants:
    """Tests for ToolScope, ToolRisk constants."""

    def test_scope_hierarchy_order(self) -> None:
        """Hierarchy is read < write < admin."""
        h = ToolScope.HIERARCHY
        assert h == ("read", "write", "admin")
        assert h.index(ToolScope.READ) < h.index(ToolScope.WRITE)
        assert h.index(ToolScope.WRITE) < h.index(ToolScope.ADMIN)

    def test_risk_values(self) -> None:
        """Risk levels are distinct strings."""
        risks = {ToolRisk.SAFE, ToolRisk.CONFIRM, ToolRisk.DENY}
        assert len(risks) == 3


class TestToolPolicy:
    """Tests for ToolPolicy."""

    def test_default_policy(self) -> None:
        """Default policy: read=safe, write=confirm, admin=deny."""
        p = ToolPolicy(tool_name="test")
        assert p.risk_for_scope(ToolScope.READ) == ToolRisk.SAFE
        assert p.risk_for_scope(ToolScope.WRITE) == ToolRisk.CONFIRM
        assert p.risk_for_scope(ToolScope.ADMIN) == ToolRisk.DENY

    def test_custom_policy(self) -> None:
        """Custom policy overrides defaults."""
        p = ToolPolicy(
            tool_name="trusted_tool",
            scope_risk={
                ToolScope.READ: ToolRisk.SAFE,
                ToolScope.WRITE: ToolRisk.SAFE,  # Trusted tool
                ToolScope.ADMIN: ToolRisk.CONFIRM,
            },
        )
        assert p.risk_for_scope(ToolScope.WRITE) == ToolRisk.SAFE
        assert p.risk_for_scope(ToolScope.ADMIN) == ToolRisk.CONFIRM

    def test_unknown_scope_denied(self) -> None:
        """Unknown scope returns DENY."""
        p = ToolPolicy(tool_name="test")
        assert p.risk_for_scope("unknown") == ToolRisk.DENY

    def test_denied_patterns_stored(self) -> None:
        """Denied patterns are kept."""
        p = ToolPolicy(
            tool_name="cmd",
            denied_patterns=(r"rm\s+-rf", r":\(\)\{"),
        )
        assert len(p.denied_patterns) == 2

    def test_repr(self) -> None:
        """ToolPolicy has readable repr."""
        p = ToolPolicy(tool_name="test")
        assert "ToolPolicy" in repr(p)
        assert "test" in repr(p)


class TestScopedToolBuilder:
    """Tests for Permissions.tool() with scope parameter."""

    @pytest.mark.parametrize(
        ("tool", "scope", "expected"),
        [
            ("sql", None, "tool:sql"),
            ("sql", "read", "tool:sql:read"),
            ("sql", "write", "tool:sql:write"),
            ("sql", "admin", "tool:sql:admin"),
            ("cmd", ToolScope.READ, "tool:cmd:read"),
            ("cmd", ToolScope.WRITE, "tool:cmd:write"),
            ("cmd", ToolScope.ADMIN, "tool:cmd:admin"),
        ],
        ids=["unscoped", "read", "write", "admin", "const-read", "const-write", "const-admin"],
    )
    def test_builder(self, tool, scope, expected) -> None:
        args = (tool,) if scope is None else (tool, scope)
        assert Permissions.tool(*args) == expected


class TestHasToolScopeAccess:
    """Tests for has_tool_scope_access() with scope hierarchy."""

    @pytest.mark.parametrize(
        ("perms", "tool", "scope", "expected"),
        [
            # Exact scope match
            ((Permissions.tool("sql", "read"),), "sql", ToolScope.READ, True),
            ((Permissions.tool("sql", "read"),), "sql", ToolScope.WRITE, False),
            # Write implies read
            ((Permissions.tool("sql", "write"),), "sql", ToolScope.READ, True),
            ((Permissions.tool("sql", "write"),), "sql", ToolScope.WRITE, True),
            ((Permissions.tool("sql", "write"),), "sql", ToolScope.ADMIN, False),
            # Admin implies all
            ((Permissions.tool("sql", "admin"),), "sql", ToolScope.READ, True),
            ((Permissions.tool("sql", "admin"),), "sql", ToolScope.WRITE, True),
            ((Permissions.tool("sql", "admin"),), "sql", ToolScope.ADMIN, True),
            # Unscoped grants all
            ((Permissions.tool("sql"),), "sql", ToolScope.ADMIN, True),
            # Wildcards
            ((Permissions.TOOL_ALL,), "sql", ToolScope.ADMIN, True),
            ((Permissions.ADMIN_ALL,), "anything", ToolScope.ADMIN, True),
            # Cross-tool denied
            ((Permissions.tool("sql", "admin"),), "cmd", ToolScope.READ, False),
            # Unknown scope denied
            ((Permissions.tool("sql", "admin"),), "sql", "superadmin", False),
        ],
        ids=[
            "exact-read",
            "exact-no-write",
            "write-implies-read",
            "write-grants-write",
            "write-no-admin",
            "admin-read",
            "admin-write",
            "admin-admin",
            "unscoped-all",
            "wildcard",
            "admin-all",
            "cross-tool-denied",
            "unknown-scope",
        ],
    )
    def test_scope_hierarchy(self, perms, tool, scope, expected) -> None:
        assert has_tool_scope_access(perms, tool, scope) is expected


class TestCheckToolScope:
    """Tests for check_tool_scope() — combined CAN + SHOULD.

    Score 4: +2 security behavior (HITL matrix), +2 breaks when risk mapping wrong.
    """

    @pytest.mark.parametrize(
        ("perms", "tool", "scope", "policy", "expected"),
        [
            # No permission = DENY
            ((Permissions.BRAIN_READ,), "sql", ToolScope.READ, None, ToolRisk.DENY),
            # Read + default policy = SAFE
            ((Permissions.tool("sql", "read"),), "sql", ToolScope.READ, None, ToolRisk.SAFE),
            # Write + default = CONFIRM (HITL)
            ((Permissions.tool("sql", "write"),), "sql", ToolScope.WRITE, None, ToolRisk.CONFIRM),
            # Admin + default = DENY
            ((Permissions.tool("sql", "admin"),), "sql", ToolScope.ADMIN, None, ToolRisk.DENY),
            # Write implies read
            ((Permissions.tool("sql", "write"),), "sql", ToolScope.READ, None, ToolRisk.SAFE),
            # SQL real scenario: SELECT ok
            ((Permissions.tool("sql", "write"),), "sql", ToolScope.READ, DEFAULT_TOOL_POLICIES["sql"], ToolRisk.SAFE),
            # SQL real scenario: INSERT HITL
            (
                (Permissions.tool("sql", "write"),),
                "sql",
                ToolScope.WRITE,
                DEFAULT_TOOL_POLICIES["sql"],
                ToolRisk.CONFIRM,
            ),
            # SQL real scenario: DELETE blocked (no admin perm)
            ((Permissions.tool("sql", "write"),), "sql", ToolScope.ADMIN, DEFAULT_TOOL_POLICIES["sql"], ToolRisk.DENY),
            # CMD real scenario
            (
                (Permissions.tool("execute_cmd", "write"),),
                "execute_cmd",
                ToolScope.READ,
                DEFAULT_TOOL_POLICIES["execute_cmd"],
                ToolRisk.SAFE,
            ),
            (
                (Permissions.tool("execute_cmd", "write"),),
                "execute_cmd",
                ToolScope.WRITE,
                DEFAULT_TOOL_POLICIES["execute_cmd"],
                ToolRisk.CONFIRM,
            ),
            (
                (Permissions.tool("execute_cmd", "write"),),
                "execute_cmd",
                ToolScope.ADMIN,
                DEFAULT_TOOL_POLICIES["execute_cmd"],
                ToolRisk.DENY,
            ),
        ],
        ids=[
            "no-perm-deny",
            "read-safe",
            "write-confirm",
            "admin-deny",
            "write-implies-read",
            "sql-read",
            "sql-write",
            "sql-admin",
            "cmd-read",
            "cmd-write",
            "cmd-admin",
        ],
    )
    def test_risk_matrix(self, perms, tool, scope, policy, expected) -> None:
        result = check_tool_scope(perms, tool, scope, policy) if policy else check_tool_scope(perms, tool, scope)
        assert result == expected

    def test_custom_policy_overrides(self) -> None:
        """Custom policy with write=safe overrides default.

        Score 4: +2 behavior, +2 breaks if policy override broken.
        """
        perms = (Permissions.tool("trusted", "write"),)
        policy = ToolPolicy(
            tool_name="trusted",
            scope_risk={
                ToolScope.READ: ToolRisk.SAFE,
                ToolScope.WRITE: ToolRisk.SAFE,
                ToolScope.ADMIN: ToolRisk.CONFIRM,
            },
        )
        assert check_tool_scope(perms, "trusted", ToolScope.WRITE, policy) == ToolRisk.SAFE


class TestRegistrationPermissions:
    """Tests for registration permission builder and access check."""

    def test_register_builder(self) -> None:
        """Permissions.register() creates tools:register:{id} permission."""
        assert Permissions.register("tenant_a") == "tools:register:tenant_a"
        assert Permissions.register("tenant_b") == "tools:register:tenant_b"

    def test_register_constant(self) -> None:
        """TOOLS_REGISTER constant is the generic form."""
        assert Permissions.TOOLS_REGISTER == "tools:register"

    @pytest.mark.parametrize(
        ("perms", "project_id", "expected"),
        [
            # Generic register is NOT sufficient
            ((Permissions.TOOLS_REGISTER,), "tenant_a", False),
            # Project-specific grants only that project
            ((Permissions.register("tenant_a"),), "tenant_a", True),
            ((Permissions.register("tenant_a"),), "tenant_b", False),
            # admin:all grants all
            ((Permissions.ADMIN_ALL,), "anything", True),
            # Non-registration perms denied
            ((Permissions.BRAIN_READ, Permissions.MEMORY_WRITE), "tenant_a", False),
            # Empty denied
            ((), "tenant_a", False),
            # Multi-project: each grants independently
            ((Permissions.register("tenant_a"), Permissions.register("tenant_b")), "tenant_a", True),
            ((Permissions.register("tenant_a"), Permissions.register("tenant_b")), "acme", False),
        ],
        ids=[
            "generic-denied",
            "project-specific-hit",
            "project-specific-miss",
            "admin-all",
            "non-registration",
            "empty",
            "multi-project-hit",
            "multi-project-miss",
        ],
    )
    def test_registration_access(self, perms, project_id, expected) -> None:
        assert has_registration_access(perms, project_id) is expected

    def test_with_token(self) -> None:
        """Registration permission works with ContextToken."""
        token = ContextToken(
            token_id="test",
            permissions=(Permissions.register("tenant_a"),),
            allowed_tenants=("tenant_a",),
        )
        assert has_registration_access(token.permissions, "tenant_a") is True
        assert has_registration_access(token.permissions, "acme") is False


class TestValidateAttenuationPermissions:
    """Tests for validate_attenuation_permissions — capability attenuation logic."""

    @staticmethod
    def _validate(parent, child):
        from contextunity.core.permissions.validation import validate_attenuation_permissions

        return validate_attenuation_permissions(parent, child)

    def test_none_returns_parent_tuple(self) -> None:
        """None requested → returns parent tuple preserving order."""
        parent = ("memory:write", "brain:read")
        result = self._validate(parent, None)
        assert result == ("memory:write", "brain:read")
        assert isinstance(result, tuple)

    @pytest.mark.parametrize(
        ("parent", "child", "expected"),
        [
            (("brain:read", "memory:write"), ("brain:read",), ("brain:read",)),
            (("brain:read", "memory:write"), ("brain:read", "memory:write"), ("brain:read", "memory:write")),
            (("brain:read",), (), ()),
            (
                ("admin:all",),
                ("admin:read", "admin:write", "admin:trace"),
                ("admin:read", "admin:write", "admin:trace"),
            ),
            (("memory:write",), ("memory:read",), ("memory:read",)),
            (("brain:write",), ("brain:read",), ("brain:read",)),
            (
                (Permissions.ADMIN_ALL,),
                (Permissions.BRAIN_READ, Permissions.MEMORY_WRITE),
                (Permissions.BRAIN_READ, Permissions.MEMORY_WRITE),
            ),
            ((Permissions.GRAPH_DISPATCHER,), (Permissions.GRAPH_RAG,), (Permissions.GRAPH_RAG,)),
        ],
        ids=[
            "subset",
            "exact",
            "empty-child",
            "admin-components",
            "write-implies-read",
            "brain-write-read",
            "admin-all-to-leaves",
            "dispatcher-to-rag",
        ],
    )
    def test_valid_attenuation(self, parent, child, expected) -> None:
        """Valid attenuation paths pass and return expected permissions."""
        assert self._validate(parent, child) == expected

    def test_excess_permission_raises_with_diagnostics(self) -> None:
        """Excess permissions → SecurityError with unauthorized name and parent scope."""
        from contextunity.core.exceptions import SecurityError

        parent = ("brain:read",)
        child = ("brain:read", "memory:write", "trace:read")
        with pytest.raises(SecurityError, match="memory:write") as exc_info:
            self._validate(parent, child)
        assert "Parent had" in str(exc_info.value)

    def test_excess_with_partial_overlap(self) -> None:
        """Some allowed, some not — only unauthorized in error."""
        from contextunity.core.exceptions import SecurityError

        parent = (Permissions.BRAIN_READ, Permissions.MEMORY_READ)
        child = (Permissions.BRAIN_READ, Permissions.TRACE_WRITE)
        with pytest.raises(SecurityError, match="trace:write"):
            self._validate(parent, child)

    def test_single_part_permission_excess(self) -> None:
        """Permission without colon (single part) rejected."""
        from contextunity.core.exceptions import SecurityError

        with pytest.raises(SecurityError):
            self._validate(("brain:read",), ("unauthorized",))

    def test_scoped_tool_allowed_by_unscoped_parent(self) -> None:
        """Parent with tool:sql allows child with tool:sql:read (ancestor walk).

        This exercises the depth-walking loop:
        excess = {tool:sql:read}  (not in parent_expanded directly)
        parts = ['tool', 'sql', 'read'] → len >= 2
        prefix = 'tool' → 'tool:*' NOT in parent_expanded
        depth=2 → ancestor = 'tool:sql' → IS in parent_expanded → allowed
        """
        parent = ("tool:sql",)
        child = ("tool:sql:read",)
        result = self._validate(parent, child)
        assert result == ("tool:sql:read",)

    def test_scoped_tool_blocked_without_parent_scope(self) -> None:
        """Parent with tool:cmd does NOT grant tool:sql:read."""
        from contextunity.core.exceptions import SecurityError

        parent = ("tool:cmd",)
        child = ("tool:sql:read",)
        with pytest.raises(SecurityError, match="tool:sql:read"):
            self._validate(parent, child)

    def test_wildcard_prefix_allows_any_action(self) -> None:
        """Parent with tool:* allows any tool:X child.

        Exercises prefix = 'tool' → f'{prefix}:*' = 'tool:*' in parent → continue.
        """
        parent = ("tool:*",)
        child = ("tool:sql:admin",)
        result = self._validate(parent, child)
        assert result == ("tool:sql:admin",)

    def test_wildcard_prefix_wrong_domain_blocked(self) -> None:
        """Parent with tool:* does NOT allow graph:rag."""
        from contextunity.core.exceptions import SecurityError

        parent = ("tool:*",)
        child = ("graph:rag",)
        with pytest.raises(SecurityError, match="graph:rag"):
            self._validate(parent, child)

    def test_deep_ancestor_walk_three_levels(self) -> None:
        """Parent with a:b allows a:b:c:d (3+ depth walk).

        parts = ['a', 'b', 'c', 'd'] → depth=2 → 'a:b' → found.
        """
        parent = ("a:b",)
        child = ("a:b:c:d",)
        result = self._validate(parent, child)
        assert result == ("a:b:c:d",)

    def test_depth_walk_partial_mismatch(self) -> None:
        """Parent with a:x does NOT allow a:b:c (ancestor 'a:b' != 'a:x')."""
        from contextunity.core.exceptions import SecurityError

        parent = ("a:x",)
        child = ("a:b:c",)
        with pytest.raises(SecurityError):
            self._validate(parent, child)

    def test_mixed_wildcard_and_specific(self) -> None:
        """Parent with tool:* and brain:read — mixed wildcard/specific."""
        parent = ("tool:*", "brain:read")
        child = ("tool:sql:write", "brain:read")
        result = self._validate(parent, child)
        assert result == ("tool:sql:write", "brain:read")


pytestmark = pytest.mark.unit
