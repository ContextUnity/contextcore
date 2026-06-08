"""Tests for ``coerce_struct_data`` boundary normalization."""

from __future__ import annotations

from contextunity.core.sdk.types import coerce_struct_data


def test_coerce_struct_data_converts_set_to_sorted_json_list() -> None:
    assert coerce_struct_data({"tags": {"b", "a", 1}}) == {"tags": [1, "a", "b"]}


def test_coerce_struct_data_converts_frozenset_to_sorted_json_list() -> None:
    assert coerce_struct_data(frozenset({"z", "y"})) == ["y", "z"]


pytestmark = __import__("pytest").mark.unit
