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


def test_pattern_from_str():
    p = sl.Pattern.from_str("??34")
    assert str(p) == "??34"
    assert len(p) == 2
    assert p[0] == sl.MaskedByte.wildcard()
    assert p[1] == sl.MaskedByte.new(0x34, 1)

    p = sl.Pattern.from_str("1234")
    assert str(p) == "1234"
    assert len(p) == 2
    assert p[0] == sl.MaskedByte.new(0x12, 1)
    assert p[1] == sl.MaskedByte.new(0x34, 1)


def test_pattern_matches():
    p = sl.Pattern.from_str("??34")
    assert p.matches(b"\x12\x34")

    p = sl.Pattern.from_str("1234")
    assert p.matches(b"\x12\x34")

    p = sl.Pattern.from_str("??34")
    assert not p.matches(b"\x12\x35")

    p = sl.Pattern.from_str("1234")
    assert not p.matches(b"\x12\x35")


def test_pattern_intersect():
    a = sl.Pattern.from_str("??34")
    b = sl.Pattern.from_str("??34")
    assert str(a.intersect(b)) == "??34"

    a = sl.Pattern.from_str("??34")
    b = sl.Pattern.from_str("??35")
    assert not a.intersect(b)

    a = sl.Pattern.from_str("??34")
    b = sl.Pattern.from_str("12??")
    assert str(a.intersect(b)) == "1234"


def test_pattern_union():
    a = sl.Pattern.from_str("??34")
    b = sl.Pattern.from_str("??34")
    assert str(a.union(b)) == "??34"

    a = sl.Pattern.from_str("??34")
    b = sl.Pattern.from_str("??35")
    assert str(a.union(b)) == "????"

    a = sl.Pattern.from_str("??34")
    b = sl.Pattern.from_str("12??")
    assert str(a.union(b)) == "????"

    a = sl.Pattern.from_str("??34")
    b = sl.Pattern.from_str("1234")
    assert str(a.union(b)) == "??34"


def test_pattern_data():
    p = sl.Pattern.from_str("??34")
    assert bytes(p.data()) == b"\x00\x34"

    p = sl.Pattern.from_str("1234")
    assert bytes(p.data()) == b"\x12\x34"


def test_pattern_mask():
    p = sl.Pattern.from_str("??34")
    assert list(p.mask()) == [0, 1]

    p = sl.Pattern.from_str("1234")
    assert list(p.mask()) == [1, 1]


def test_function_info_new():
    p = sl.Pattern.from_str("??34")
    f = sl.FunctionInfo([p])
    assert f.patterns == [p]


def test_function_node_new():
    f = sl.FunctionNode("test")
    assert str(f) == "<func:test:>"
    assert f.is_bridge == True

    f.ref_count = 1
    assert f.is_bridge == False


def test_trie_node_new():
    def node(s: str, ref_count: int = 0) -> sl.FunctionNode:
        r = sl.FunctionNode(s)
        r.ref_count = ref_count
        return r

    def info(s: str) -> sl.FunctionInfo:
        return sl.FunctionInfo([sl.Pattern.from_str(s)])

    trie = sl.new_trie()
    assert len(trie.children) == 0

    # pattern <MIN_PATTERN_LENGTH
    assert trie_ops.trie_insert_funcs(trie, {node("f1"): info("11")}) == 0
    assert (
        trie_ops.trie_insert_funcs(
            trie, {node("f1"): info("11" * sl.MIN_PATTERN_LENGTH)}
        )
        == 1
    )

    # need >MIN_PATTERN_LENGTH of masked bytes
    assert (
        trie_ops.trie_insert_funcs(
            trie, {node("f1"): info("11" * (sl.MIN_PATTERN_LENGTH - 1) + "??")}
        )
        == 0
    )
    assert (
        trie_ops.trie_insert_funcs(
            trie, {node("f1"): info("11" * (sl.MIN_PATTERN_LENGTH - 1) + "??22")}
        )
        == 1
    )

    funcs = {
        node("f1"): info("1122334455667788"),
        node("f2"): info("1122334455667788"),
        node("f3"): info("1122334455667788"),
    }

    trie = sl.new_trie()
    assert len(trie.children) == 0

    assert trie_ops.trie_insert_funcs(trie, funcs) == 3
    assert len(trie.children) == 1
    # trie_ops.finalize_trie(trie, funcs)
    # assert len(trie.children) == 1

    assert list(trie.all_functions()) == [node("f1", 1), node("f2", 1), node("f3", 1)]
