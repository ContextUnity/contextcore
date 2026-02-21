"""Tests for permissions registry and identity scoping."""

from __future__ import annotations

from contextcore import (
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

    def test_admin_all_expands(self) -> None:
        """admin:all expands to all admin + service permissions."""
        result = expand_permissions((Permissions.ADMIN_ALL,))
        assert Permissions.ADMIN_ALL in result
        assert Permissions.ADMIN_READ in result
        assert Permissions.ADMIN_WRITE in result
        assert Permissions.ADMIN_TRACE in result
        assert Permissions.BRAIN_READ in result
        assert Permissions.BRAIN_WRITE in result
        assert Permissions.MEMORY_READ in result
        assert Permissions.MEMORY_WRITE in result
        assert Permissions.TRACE_READ in result
        assert Permissions.TRACE_WRITE in result

    def test_memory_write_implies_read(self) -> None:
        """memory:write implies memory:read."""
        result = expand_permissions((Permissions.MEMORY_WRITE,))
        assert Permissions.MEMORY_WRITE in result
        assert Permissions.MEMORY_READ in result

    def test_brain_write_implies_read(self) -> None:
        """brain:write implies brain:read."""
        result = expand_permissions((Permissions.BRAIN_WRITE,))
        assert Permissions.BRAIN_WRITE in result
        assert Permissions.BRAIN_READ in result

    def test_graph_dispatcher_implies_all_graphs(self) -> None:
        """graph:dispatcher implies all graph types."""
        result = expand_permissions((Permissions.GRAPH_DISPATCHER,))
        assert Permissions.GRAPH_RAG in result
        assert Permissions.GRAPH_COMMERCE in result
        assert Permissions.GRAPH_NEWS in result
        assert Permissions.GRAPH_MEDICAL in result

    def test_admin_trace_implies_trace_read(self) -> None:
        """admin:trace implies trace:read."""
        result = expand_permissions((Permissions.ADMIN_TRACE,))
        assert Permissions.ADMIN_TRACE in result
        assert Permissions.TRACE_READ in result

    def test_no_expansion_for_leaf(self) -> None:
        """Leaf permissions don't expand."""
        result = expand_permissions((Permissions.BRAIN_READ,))
        assert result == (Permissions.BRAIN_READ,)

    def test_deduplication(self) -> None:
        """Duplicates in input are deduplicated."""
        result = expand_permissions(
            (
                Permissions.BRAIN_READ,
                Permissions.BRAIN_READ,
            )
        )
        assert result.count(Permissions.BRAIN_READ) == 1

    def test_transitive_expansion(self) -> None:
        """admin:all → admin:trace → trace:read (transitive)."""
        result = expand_permissions((Permissions.ADMIN_ALL,))
        assert Permissions.TRACE_READ in result  # via admin:trace

    def test_empty_input(self) -> None:
        """Empty input returns empty tuple."""
        assert expand_permissions(()) == ()


class TestNamespaceProfiles:
    """Tests for NAMESPACE_PROFILES mapping."""

    def test_all_namespaces_have_profiles(self) -> None:
        """Every UserNamespace has a corresponding profile."""
        for ns in UserNamespace.ALL:
            assert ns in NAMESPACE_PROFILES, f"Missing profile for namespace: {ns}"

    def test_free_profile_is_minimal(self) -> None:
        """Free profile only gives RAG read access."""
        perms = NAMESPACE_PROFILES[UserNamespace.FREE]
        assert Permissions.GRAPH_RAG in perms
        assert Permissions.BRAIN_READ in perms
        assert Permissions.MEMORY_WRITE not in perms
        assert Permissions.TRACE_WRITE not in perms

    def test_pro_profile_has_memory(self) -> None:
        """Pro profile includes memory access."""
        perms = NAMESPACE_PROFILES[UserNamespace.PRO]
        assert Permissions.MEMORY_READ in perms
        assert Permissions.MEMORY_WRITE in perms
        assert Permissions.TRACE_WRITE in perms

    def test_admin_profile_is_admin_all(self) -> None:
        """Admin profile is just admin:all."""
        perms = NAMESPACE_PROFILES[UserNamespace.ADMIN]
        assert Permissions.ADMIN_ALL in perms


class TestProjectProfiles:
    """Tests for PROJECT_PROFILES."""

    def test_known_profiles(self) -> None:
        """All expected profiles exist."""
        assert "rag_readonly" in PROJECT_PROFILES
        assert "rag_full" in PROJECT_PROFILES
        assert "commerce" in PROJECT_PROFILES
        assert "medical" in PROJECT_PROFILES
        assert "admin" in PROJECT_PROFILES


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
            allowed_tenants=["nszu"],
        )
        assert token.user_id == "dr_ivanov"
        assert token.agent_id == "dispatcher"
        assert token.user_namespace == "pro"
        assert token.allowed_tenants == ("nszu",)

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
            allowed_tenants=["nszu"],
        )
        child = builder.attenuate(
            parent,
            permissions=[Permissions.BRAIN_READ],
            agent_id="rag_agent",
        )
        # user_id and user_namespace inherited
        assert child.user_id == "dr_ivanov"
        assert child.user_namespace == "pro"
        assert child.allowed_tenants == ("nszu",)
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
            allowed_tenants=["traverse"],
        )
        assert token.user_id is None
        assert token.agent_id == "gardener"
        assert token.user_namespace == "system"


class TestTokenIdentitySerialization:
    """Tests for identity fields in token serialization roundtrip."""

    def test_roundtrip_with_identity(self) -> None:
        """Token with identity fields survives serialization roundtrip."""
        from contextcore.signing import UnsignedBackend
        from contextcore.token_utils import parse_token_string, serialize_token

        backend = UnsignedBackend()
        token = ContextToken(
            token_id="test_roundtrip",
            permissions=(Permissions.BRAIN_READ, Permissions.MEMORY_WRITE),
            allowed_tenants=("nszu",),
            exp_unix=9999999999.0,
            user_id="dr_ivanov",
            agent_id="dispatcher",
            user_namespace="pro",
        )
        serialized = serialize_token(token, backend=backend)
        parsed = parse_token_string(serialized, backend=backend)

        assert parsed is not None
        assert parsed.token_id == "test_roundtrip"
        assert parsed.user_id == "dr_ivanov"
        assert parsed.agent_id == "dispatcher"
        assert parsed.user_namespace == "pro"

    def test_roundtrip_default_namespace(self) -> None:
        """Token with default namespace omits it in serialization (compact)."""
        from contextcore.signing import UnsignedBackend
        from contextcore.token_utils import parse_token_string, serialize_token

        backend = UnsignedBackend()
        token = ContextToken(
            token_id="minimal",
            permissions=(Permissions.BRAIN_READ,),
            exp_unix=9999999999.0,
        )
        serialized = serialize_token(token, backend=backend)
        # "default" namespace should NOT appear in serialized data
        assert "user_namespace" not in serialized

        parsed = parse_token_string(serialized, backend=backend)
        assert parsed is not None
        assert parsed.user_namespace == "default"
        assert parsed.user_id is None
        assert parsed.agent_id is None

    def test_backward_compat_old_token(self) -> None:
        """Old tokens without identity fields parse with defaults."""
        from contextcore.signing import UnsignedBackend
        from contextcore.token_utils import parse_token_string, serialize_token

        backend = UnsignedBackend()
        # Simulate old token (no identity fields)
        token = ContextToken(
            token_id="legacy",
            permissions=("read:data",),
            exp_unix=9999999999.0,
        )
        serialized = serialize_token(token, backend=backend)
        parsed = parse_token_string(serialized, backend=backend)

        assert parsed is not None
        assert parsed.user_id is None
        assert parsed.agent_id is None
        assert parsed.user_namespace == "default"


class TestPermissionBuilders:
    """Tests for Permissions.tool(), .graph(), .service() builders."""

    def test_tool_builder(self) -> None:
        """Permissions.tool() creates tool:name permission."""
        assert Permissions.tool("brain_search") == "tool:brain_search"
        assert Permissions.tool("shield_scan") == "tool:shield_scan"
        assert Permissions.tool("my_custom_tool") == "tool:my_custom_tool"

    def test_graph_builder(self) -> None:
        """Permissions.graph() creates graph:name permission."""
        assert Permissions.graph("rag_retrieval") == "graph:rag_retrieval"
        assert Permissions.graph("commerce_search") == "graph:commerce_search"

    def test_service_builder(self) -> None:
        """Permissions.service() creates domain:action permission."""
        assert Permissions.service("brain", "read") == "brain:read"
        assert Permissions.service("memory", "write") == "memory:write"

    def test_tool_builder_matches_constant(self) -> None:
        """Builder output matches predefined constants."""
        assert Permissions.tool("brain_search") == Permissions.TOOL_BRAIN_SEARCH
        assert Permissions.tool("web_search") == Permissions.TOOL_WEB_SEARCH
        assert Permissions.tool("sql") == Permissions.TOOL_SQL

    def test_graph_builder_matches_constant(self) -> None:
        """Builder output matches predefined constants."""
        assert Permissions.graph("rag") == Permissions.GRAPH_RAG
        assert Permissions.graph("commerce") == Permissions.GRAPH_COMMERCE

    def test_service_builder_matches_constant(self) -> None:
        """Builder output matches predefined constants."""
        assert Permissions.service("brain", "read") == Permissions.BRAIN_READ
        assert Permissions.service("dispatcher", "execute") == Permissions.DISPATCHER_EXECUTE

    def test_builder_in_mint_root(self) -> None:
        """Builders work with TokenBuilder.mint_root()."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=[
                Permissions.tool("brain_search"),
                Permissions.tool("shield_scan"),
                Permissions.graph("rag_retrieval"),
            ],
            ttl_s=300,
        )
        assert token.has_permission("tool:brain_search")
        assert token.has_permission("tool:shield_scan")
        assert token.has_permission("graph:rag_retrieval")
        assert not token.has_permission("tool:sql_execute")


class TestHasToolAccess:
    """Tests for has_tool_access() helper."""

    def test_exact_match(self) -> None:
        """Exact tool name grants access."""
        perms = (Permissions.tool("brain_search"), Permissions.tool("shield_scan"))
        assert has_tool_access(perms, "brain_search") is True
        assert has_tool_access(perms, "shield_scan") is True
        assert has_tool_access(perms, "sql_execute") is False

    def test_wildcard_grants_all(self) -> None:
        """tool:* grants access to any tool."""
        perms = (Permissions.TOOL_ALL,)
        assert has_tool_access(perms, "brain_search") is True
        assert has_tool_access(perms, "anything_at_all") is True

    def test_admin_all_grants_tools(self) -> None:
        """admin:all grants access to any tool."""
        perms = (Permissions.ADMIN_ALL,)
        assert has_tool_access(perms, "brain_search") is True
        assert has_tool_access(perms, "anything") is True

    def test_no_tool_permissions(self) -> None:
        """Service permissions don't grant tool access."""
        perms = (Permissions.BRAIN_READ, Permissions.MEMORY_WRITE)
        assert has_tool_access(perms, "brain_search") is False

    def test_empty_permissions(self) -> None:
        """Empty permissions deny everything."""
        assert has_tool_access((), "brain_search") is False


class TestHasGraphAccess:
    """Tests for has_graph_access() helper."""

    def test_exact_match(self) -> None:
        """Exact graph name grants access."""
        perms = (Permissions.graph("rag_retrieval"),)
        assert has_graph_access(perms, "rag_retrieval") is True
        assert has_graph_access(perms, "commerce_search") is False

    def test_wildcard_grants_all(self) -> None:
        """graph:* grants access to any graph."""
        perms = (Permissions.GRAPH_ALL,)
        assert has_graph_access(perms, "rag_retrieval") is True
        assert has_graph_access(perms, "any_custom_graph") is True

    def test_dispatcher_implies_all(self) -> None:
        """graph:dispatcher grants access to all graphs."""
        perms = (Permissions.GRAPH_DISPATCHER,)
        assert has_graph_access(perms, "rag_retrieval") is True
        assert has_graph_access(perms, "commerce_search") is True

    def test_admin_all_grants_graphs(self) -> None:
        """admin:all grants access to any graph."""
        perms = (Permissions.ADMIN_ALL,)
        assert has_graph_access(perms, "any_graph") is True

    def test_no_graph_permissions(self) -> None:
        """Service permissions don't grant graph access."""
        perms = (Permissions.BRAIN_READ,)
        assert has_graph_access(perms, "rag_retrieval") is False


class TestExtractToolNames:
    """Tests for extract_tool_names() helper."""

    def test_extracts_names(self) -> None:
        """Extracts concrete tool names from permissions."""
        perms = ("tool:brain_search", "tool:shield_scan", "brain:read")
        result = extract_tool_names(perms)
        assert result == frozenset({"brain_search", "shield_scan"})

    def test_wildcard_returns_star(self) -> None:
        """Wildcard returns frozenset with '*'."""
        perms = (Permissions.TOOL_ALL, "brain:read")
        result = extract_tool_names(perms)
        assert result == frozenset({"*"})

    def test_admin_all_returns_star(self) -> None:
        """admin:all returns frozenset with '*'."""
        perms = (Permissions.ADMIN_ALL,)
        result = extract_tool_names(perms)
        assert result == frozenset({"*"})

    def test_no_tools(self) -> None:
        """No tool permissions returns empty set."""
        perms = (Permissions.BRAIN_READ, Permissions.MEMORY_WRITE)
        result = extract_tool_names(perms)
        assert result == frozenset()

    def test_builder_produced_perms(self) -> None:
        """Works with builder-produced permissions."""
        perms = (
            Permissions.tool("recall_facts"),
            Permissions.tool("remember_episode"),
            Permissions.BRAIN_READ,
        )
        result = extract_tool_names(perms)
        assert result == frozenset({"recall_facts", "remember_episode"})


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

    def test_unscoped(self) -> None:
        """No scope = full access permission."""
        assert Permissions.tool("sql") == "tool:sql"

    def test_scoped_read(self) -> None:
        assert Permissions.tool("sql", "read") == "tool:sql:read"

    def test_scoped_write(self) -> None:
        assert Permissions.tool("sql", "write") == "tool:sql:write"

    def test_scoped_admin(self) -> None:
        assert Permissions.tool("sql", "admin") == "tool:sql:admin"

    def test_scope_with_toolscope_constant(self) -> None:
        assert Permissions.tool("cmd", ToolScope.READ) == "tool:cmd:read"
        assert Permissions.tool("cmd", ToolScope.WRITE) == "tool:cmd:write"
        assert Permissions.tool("cmd", ToolScope.ADMIN) == "tool:cmd:admin"


class TestHasToolScopeAccess:
    """Tests for has_tool_scope_access() with scope hierarchy."""

    def test_exact_scope_match(self) -> None:
        """Exact scope grants access."""
        perms = (Permissions.tool("sql", "read"),)
        assert has_tool_scope_access(perms, "sql", ToolScope.READ) is True
        assert has_tool_scope_access(perms, "sql", ToolScope.WRITE) is False

    def test_write_implies_read(self) -> None:
        """Write scope implies read."""
        perms = (Permissions.tool("sql", "write"),)
        assert has_tool_scope_access(perms, "sql", ToolScope.READ) is True
        assert has_tool_scope_access(perms, "sql", ToolScope.WRITE) is True
        assert has_tool_scope_access(perms, "sql", ToolScope.ADMIN) is False

    def test_admin_implies_all(self) -> None:
        """Admin scope implies write and read."""
        perms = (Permissions.tool("sql", "admin"),)
        assert has_tool_scope_access(perms, "sql", ToolScope.READ) is True
        assert has_tool_scope_access(perms, "sql", ToolScope.WRITE) is True
        assert has_tool_scope_access(perms, "sql", ToolScope.ADMIN) is True

    def test_unscoped_grants_all(self) -> None:
        """Unscoped tool permission grants all scopes."""
        perms = (Permissions.tool("sql"),)
        assert has_tool_scope_access(perms, "sql", ToolScope.READ) is True
        assert has_tool_scope_access(perms, "sql", ToolScope.WRITE) is True
        assert has_tool_scope_access(perms, "sql", ToolScope.ADMIN) is True

    def test_wildcard_grants_all(self) -> None:
        """tool:* grants all scopes for all tools."""
        perms = (Permissions.TOOL_ALL,)
        assert has_tool_scope_access(perms, "sql", ToolScope.ADMIN) is True
        assert has_tool_scope_access(perms, "cmd", ToolScope.WRITE) is True

    def test_admin_all_grants_all(self) -> None:
        """admin:all grants everything."""
        perms = (Permissions.ADMIN_ALL,)
        assert has_tool_scope_access(perms, "anything", ToolScope.ADMIN) is True

    def test_different_tool_denied(self) -> None:
        """Permission for one tool doesn't grant access to another."""
        perms = (Permissions.tool("sql", "admin"),)
        assert has_tool_scope_access(perms, "cmd", ToolScope.READ) is False

    def test_unknown_scope(self) -> None:
        """Unknown scope is denied."""
        perms = (Permissions.tool("sql", "admin"),)
        assert has_tool_scope_access(perms, "sql", "superadmin") is False


class TestCheckToolScope:
    """Tests for check_tool_scope() — combined CAN + SHOULD."""

    def test_no_permission_denied(self) -> None:
        """No permission = DENY regardless of policy."""
        perms = (Permissions.BRAIN_READ,)  # no tool permissions
        assert check_tool_scope(perms, "sql", ToolScope.READ) == ToolRisk.DENY

    def test_read_with_permission_safe(self) -> None:
        """Read with permission and default policy = SAFE."""
        perms = (Permissions.tool("sql", "read"),)
        assert check_tool_scope(perms, "sql", ToolScope.READ) == ToolRisk.SAFE

    def test_write_with_permission_confirm(self) -> None:
        """Write with permission and default policy = CONFIRM (HITL)."""
        perms = (Permissions.tool("sql", "write"),)
        assert check_tool_scope(perms, "sql", ToolScope.WRITE) == ToolRisk.CONFIRM

    def test_admin_with_permission_deny_by_policy(self) -> None:
        """Admin with permission but default policy = DENY."""
        perms = (Permissions.tool("sql", "admin"),)
        assert check_tool_scope(perms, "sql", ToolScope.ADMIN) == ToolRisk.DENY

    def test_custom_policy_overrides(self) -> None:
        """Custom policy with write=safe overrides default."""
        perms = (Permissions.tool("trusted", "write"),)
        policy = ToolPolicy(
            tool_name="trusted",
            scope_risk={
                ToolScope.READ: ToolRisk.SAFE,
                ToolScope.WRITE: ToolRisk.SAFE,  # Trusted!
                ToolScope.ADMIN: ToolRisk.CONFIRM,
            },
        )
        assert check_tool_scope(perms, "trusted", ToolScope.WRITE, policy) == ToolRisk.SAFE

    def test_write_implies_read_in_check(self) -> None:
        """Write permission grants read, and read is SAFE."""
        perms = (Permissions.tool("sql", "write"),)
        assert check_tool_scope(perms, "sql", ToolScope.READ) == ToolRisk.SAFE

    def test_sql_real_scenario(self) -> None:
        """Real scenario: SELECT ok, INSERT HITL, DELETE blocked."""
        perms = (Permissions.tool("sql", "write"),)  # Can read + write
        policy = DEFAULT_TOOL_POLICIES["sql"]

        assert check_tool_scope(perms, "sql", ToolScope.READ, policy) == ToolRisk.SAFE
        assert check_tool_scope(perms, "sql", ToolScope.WRITE, policy) == ToolRisk.CONFIRM
        assert check_tool_scope(perms, "sql", ToolScope.ADMIN, policy) == ToolRisk.DENY  # no perm

    def test_cmd_real_scenario(self) -> None:
        """Real scenario: ls ok, sed HITL, rm blocked."""
        perms = (Permissions.tool("execute_cmd", "write"),)
        policy = DEFAULT_TOOL_POLICIES["execute_cmd"]

        assert check_tool_scope(perms, "execute_cmd", ToolScope.READ, policy) == ToolRisk.SAFE
        assert check_tool_scope(perms, "execute_cmd", ToolScope.WRITE, policy) == ToolRisk.CONFIRM
        assert check_tool_scope(perms, "execute_cmd", ToolScope.ADMIN, policy) == ToolRisk.DENY


class TestDefaultToolPolicies:
    """Tests for DEFAULT_TOOL_POLICIES."""

    def test_known_policies(self) -> None:
        """All expected default policies exist."""
        assert "sql" in DEFAULT_TOOL_POLICIES
        assert "execute_cmd" in DEFAULT_TOOL_POLICIES
        assert "file" in DEFAULT_TOOL_POLICIES

    def test_sql_policy_read_safe(self) -> None:
        assert DEFAULT_TOOL_POLICIES["sql"].risk_for_scope(ToolScope.READ) == ToolRisk.SAFE

    def test_sql_policy_admin_deny(self) -> None:
        assert DEFAULT_TOOL_POLICIES["sql"].risk_for_scope(ToolScope.ADMIN) == ToolRisk.DENY

    def test_cmd_has_denied_patterns(self) -> None:
        assert len(DEFAULT_TOOL_POLICIES["execute_cmd"].denied_patterns) > 0


class TestRegistrationPermissions:
    """Tests for registration permission builder and access check."""

    def test_register_builder(self) -> None:
        """Permissions.register() creates tools:register:{id} permission."""
        assert Permissions.register("nszu") == "tools:register:nszu"
        assert Permissions.register("traverse") == "tools:register:traverse"

    def test_register_constant(self) -> None:
        """TOOLS_REGISTER constant is the generic form."""
        assert Permissions.TOOLS_REGISTER == "tools:register"

    def test_generic_grants_all(self) -> None:
        """Generic tools:register grants registration for any project."""
        perms = (Permissions.TOOLS_REGISTER,)
        assert has_registration_access(perms, "nszu") is True
        assert has_registration_access(perms, "traverse") is True
        assert has_registration_access(perms, "anything") is True

    def test_project_specific_grants_only_that_project(self) -> None:
        """Project-specific permission grants only that project."""
        perms = (Permissions.register("nszu"),)
        assert has_registration_access(perms, "nszu") is True
        assert has_registration_access(perms, "traverse") is False
        assert has_registration_access(perms, "acme") is False

    def test_admin_all_grants_registration(self) -> None:
        """admin:all grants registration for any project."""
        perms = (Permissions.ADMIN_ALL,)
        assert has_registration_access(perms, "nszu") is True
        assert has_registration_access(perms, "anything") is True

    def test_no_registration_permission(self) -> None:
        """Non-registration permissions don't grant registration."""
        perms = (Permissions.BRAIN_READ, Permissions.MEMORY_WRITE)
        assert has_registration_access(perms, "nszu") is False

    def test_empty_permissions(self) -> None:
        """Empty permissions deny registration."""
        assert has_registration_access((), "nszu") is False

    def test_multiple_project_permissions(self) -> None:
        """Multiple project-specific permissions work independently."""
        perms = (Permissions.register("nszu"), Permissions.register("traverse"))
        assert has_registration_access(perms, "nszu") is True
        assert has_registration_access(perms, "traverse") is True
        assert has_registration_access(perms, "acme") is False

    def test_with_token(self) -> None:
        """Registration permission works with ContextToken."""
        token = ContextToken(
            token_id="test",
            permissions=(Permissions.register("nszu"),),
            allowed_tenants=("nszu",),
        )
        assert has_registration_access(token.permissions, "nszu") is True
        assert has_registration_access(token.permissions, "acme") is False
