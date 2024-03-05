from . import signaturelibrary as sl
from .signaturelibrary import (
    MaskedByte,
    Pattern,
    FunctionInfo,
    FunctionNode,
    str_to_bytes,
)

from . import trie_ops
import pytest


def test_function_info_new():
    p = Pattern.from_str("??34")
    f = FunctionInfo([p])
    assert f.patterns == [p]


def test_function_node_new():
    f = FunctionNode("test")
    assert str(f) == "<func:test:>"
    assert f.is_bridge == True

    f.ref_count = 1
    assert f.is_bridge == False


def b(s: str) -> MaskedByte:
    return MaskedByte.from_str(s)


bb = str_to_bytes


def p(s: str) -> Pattern:
    return Pattern.from_str(s)


def node(s: str, ref_count: int = 0) -> FunctionNode:
    r = FunctionNode(s)
    r.ref_count = ref_count
    return r


def info(s: str) -> FunctionInfo:
    return FunctionInfo([Pattern.from_str(s)])


def test_trie_insert_single():
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


def test_trie_insert_multiple():
    # all functions have the same pattern
    funcs = {
        node("f1"): info("1122334455667788"),
        node("f2"): info("1122334455667788"),
        node("f3"): info("1122334455667788"),
    }

    trie = sl.new_trie()
    assert len(trie.children) == 0

    assert trie_ops.trie_insert_funcs(trie, funcs) == 3
    assert list(trie.all_functions()) == [node("f1", 1), node("f2", 1), node("f3", 1)]

    # root + single child node
    assert len(trie.children) == 1
    assert len(list(trie.all_nodes())) == 2

    child = trie.children[b("11")]
    assert str(child.pattern) == "1122334455667788"
    assert len(child.children) == 0
    assert len(child.value) == 3
    assert list(child.value) == [node("f1", 1), node("f2", 1), node("f3", 1)]

    assert trie.find(bb("1122334455667788")) == [
        node("f1", 1),
        node("f2", 1),
        node("f3", 1),
    ]

    # should be a branch node
    funcs = {
        node("f1"): info("1122334455667788"),
        node("f2"): info("1122334455660088"),
    }

    trie = sl.new_trie()
    assert len(trie.children) == 0

    assert trie_ops.trie_insert_funcs(trie, funcs) == 2
    # 00 < 77?
    assert list(trie.all_functions()) == [node("f2", 1), node("f1", 1)]

    # root + single child node
    assert len(trie.children) == 1
    assert len(list(trie.all_nodes())) == 4

    assert list(trie.children.keys()) == [b("11")]
    c1 = trie.children[b("11")]
    assert str(c1.pattern) == "112233445566"
    assert list(c1.children.keys()) == [b("77"), b("00")]
    c2 = c1.children[b("77")]
    assert len(list(c2.children)) == 0
    c3 = c1.children[b("00")]
    assert len(list(c3.children)) == 0

    assert trie.find(bb("1122334455667788")) == [node("f1", 1)]
    assert trie.find(bb("1122334455660088")) == [node("f2", 1)]


def test_trie_find_wildcard():
    funcs = {
        node("f1"): info("??2233445566778899"),
        node("f2"): info("11??33445566778899"),
        node("f3"): info("1122??445566778899"),
    }

    trie = sl.new_trie()
    assert trie_ops.trie_insert_funcs(trie, funcs) == 3

    assert trie.find(bb("112233445566778899")) == [
        node("f3", 1),
        node("f2", 1),
        node("f1", 1),
    ]
    assert trie.find(bb("992233445566778899")) == [node("f1", 1)]
    assert trie.find(bb("112299445566778899")) == [node("f3", 1)]


def test_trie_finalize():
    pass
    # trie_ops.finalize_trie(trie, funcs)
    # assert len(trie.children) == 1
