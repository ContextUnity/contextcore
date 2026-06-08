"""Tests for value-level narrowing helpers."""

from __future__ import annotations

from datetime import datetime

from contextunity.core.narrowing import (
    as_float,
    as_int,
    as_json_dict,
    as_json_dict_list,
    as_json_dict_map,
    as_str,
    as_str_list,
    json_dict_list_as_json,
    optional_str_field,
    str_list_as_json,
)


def test_as_str():
    assert as_str("x") == "x"
    assert as_str(1) == ""
    assert as_str(1, default="fallback") == "fallback"


def test_as_int():
    assert as_int(42) == 42
    assert as_int("10") == 10
    assert as_int("abc", default=99) == 99
    assert as_int(True, default=0) == 0


def test_as_float():
    assert as_float(1.5) == 1.5
    assert as_float("2.5") == 2.5
    assert as_float(True, default=0.0) == 0.0


def test_as_json_dict_rejects_non_json():
    assert as_json_dict({"a": 1}) == {"a": 1}
    assert as_json_dict(datetime(2020, 1, 1)) == {}


def test_as_json_dict_list():
    assert as_json_dict_list([{"a": 1}, "x"]) == [{"a": 1}]


def test_as_json_dict_map():
    mapped = as_json_dict_map({"a": {"x": 1}, "b": "nope"})
    assert mapped == {"a": {"x": 1}}


def test_as_str_list():
    assert as_str_list(["a", 1]) == ["a", "1"]
    assert as_str_list(None) == []


def test_optional_str_field():
    assert optional_str_field({"k": "v"}, "k") == "v"
    assert optional_str_field({"k": 1}, "k") is None
    assert optional_str_field("not-a-dict", "k") is None


def test_str_list_as_json():
    assert str_list_as_json(["a"]) == ["a"]


def test_json_dict_list_as_json():
    rows = [{"id": "1"}]
    assert json_dict_list_as_json(rows) == rows
