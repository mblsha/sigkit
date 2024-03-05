from . import signaturelibrary as sl
from . import trie_ops
import pytest

# from dataclasses import dataclass
# from typing import List, NamedTuple, Optional


def test_maskedbyte_new():
    assert str(sl.MaskedByte.new(0x12, 0)) == "??"
    assert str(sl.MaskedByte.new(0x12, 1)) == "12"


def test_maskedbyte_from_str():
    assert str(sl.MaskedByte.from_str("??")) == "??"
    assert str(sl.MaskedByte.from_str("12")) == "12"

    with pytest.raises(AssertionError):
        sl.MaskedByte.from_str("123")


def test_maskedbyte_le():
    a = sl.MaskedByte.new(0x12, 1)
    b = sl.MaskedByte.new(0x13, 1)
    assert a < b

    c = sl.MaskedByte.new(0x12, 0)
    d = sl.MaskedByte.new(0x13, 0)
    assert c == d


def test_maskedbyte_matches():
    a = sl.MaskedByte.new(0x12, 1)
    b = sl.MaskedByte.new(0x12, 1)
    assert a.matches(b)

    a = sl.MaskedByte.new(0x12, 0)
    b = sl.MaskedByte.new(0x12, 0)
    assert a.matches(b)

    a = sl.MaskedByte.new(0x12, 1)
    b = sl.MaskedByte.new(0x13, 1)
    assert not a.matches(b)

    a = sl.MaskedByte.new(0x12, 0)
    b = sl.MaskedByte.new(0xFF, 1)
    assert a.matches(b)

    # !!! this is an unexpected case
    a = sl.MaskedByte.new(0x12, 1)
    b = sl.MaskedByte.new(0xFF, 0)
    assert not a.matches(b)

    assert sl.MaskedByte.new(0x12, 1).matches(0x12)
    assert not sl.MaskedByte.new(0x12, 1).matches(0x13)


def test_maskedbyte_intersect():
    a = sl.MaskedByte.new(0x12, 1)
    b = sl.MaskedByte.new(0x12, 1)
    assert str(a.intersect(b)) == "12"

    a = sl.MaskedByte.new(0x12, 1)
    b = sl.MaskedByte.new(0x13, 1)
    assert not a.intersect(b)

    a = sl.MaskedByte.new(0x12, 0)
    b = sl.MaskedByte.new(0x12, 0)
    assert str(a.intersect(b)) == "??"

    a = sl.MaskedByte.new(0x12, 0)
    b = sl.MaskedByte.new(0xFF, 0)
    assert str(a.intersect(b)) == "??"

    a = sl.MaskedByte.new(0x12, 1)
    b = sl.MaskedByte.new(0xFF, 0)
    assert str(a.intersect(b)) == "12"

    a = sl.MaskedByte.new(0x12, 0)
    b = sl.MaskedByte.new(0xFF, 1)
    assert str(a.intersect(b)) == "ff"


def test_maskedbyte_union():
    a = sl.MaskedByte.new(0x12, 0)
    b = sl.MaskedByte.new(0xFF, 0)
    assert str(a.union(b)) == "??"

    a = sl.MaskedByte.new(0x12, 1)
    b = sl.MaskedByte.new(0xFF, 0)
    assert str(a.union(b)) == "??"

    a = sl.MaskedByte.new(0x12, 0)
    b = sl.MaskedByte.new(0xFF, 1)
    assert str(a.union(b)) == "??"

    a = sl.MaskedByte.new(0x12, 1)
    b = sl.MaskedByte.new(0xFF, 1)
    assert str(a.union(b)) == "??"

    a = sl.MaskedByte.new(0x12, 1)
    b = sl.MaskedByte.new(0x12, 1)
    assert str(a.union(b)) == "12"


def test_pattern_new():
    p = sl.Pattern(b"\x12\x34", [0, 1])
    assert str(p) == "??34"


def test_function_node_new():
    f = sl.FunctionNode("test")
    assert str(f) == "<func:test>"


def test_trie_node_new():
    key = sl.FunctionNode("test")
    value = sl.FunctionInfo()
    value.patterns = [sl.Pattern(b"\x12\x34", [1, 1])]
    value.aliases = []
    value.callees = {}
    funcs = {
        key: value,
    }

    trie = sl.new_trie()
    assert len(trie.children) == 0
    # spy = mocker.spy(foo, 'bar')

    trie_ops.trie_insert_funcs(trie, funcs)
    assert len(trie.children) == 1
    trie_ops.finalize_trie(trie, funcs)
    assert len(trie.children) == 1

    assert list(trie.all_nodes()) == [key]
