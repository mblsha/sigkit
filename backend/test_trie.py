from .signaturelibrary import (
    FunctionInfo,
    FunctionNode,
    TrieNode,
)

from . import signaturelibrary as sl
from .test_trie_util import node, info, p, b, bb
from . import trie_ops

import pytest


def test_function_info_new() -> None:
    p1 = p("??34")
    p2 = p("1234")
    f = FunctionInfo([p1, p2])
    assert f.patterns == [p1, p2]


def test_function_node_new() -> None:
    f = FunctionNode("test")
    assert str(f) == "<func:test:>"
    assert f.is_bridge == True

    f.ref_count = 1
    assert f.is_bridge == False


def test_trie_node_eq() -> None:
    t1 = TrieNode.new_trie()
    t2 = TrieNode.new_trie()
    assert t1 == t2

    t1 = TrieNode(p("??34"), {}, None)
    t2 = TrieNode(p("??34"), {}, None)
    assert t1 == t2

    t1 = TrieNode(p("??34"), {}, None)
    t2 = TrieNode(p("1234"), {}, None)
    assert t1 != t2

    t1 = TrieNode(p("??34"), {b("11"): TrieNode.new_trie()}, None)
    t2 = TrieNode(p("??34"), {b("11"): TrieNode.new_trie()}, None)
    assert t1 == t2

    t1 = TrieNode(p("??34"), {b("11"): TrieNode.new_trie()}, None)
    t2 = TrieNode(p("??34"), {b("22"): TrieNode.new_trie()}, None)
    assert t1 != t2


def test_trie_insert_single() -> None:
    trie = TrieNode.new_trie()
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


def test_trie_insert_multiple() -> None:
    # all functions have the same pattern
    funcs = {
        node("f1"): info("1122334455667788"),
        node("f2"): info("1122334455667788"),
        node("f3"): info("1122334455667788"),
    }

    trie = TrieNode.new_trie()
    assert len(trie.children) == 0

    assert trie_ops.trie_insert_funcs(trie, funcs) == 3
    assert list(trie.all_functions()) == [node("f1", 1), node("f2", 1), node("f3", 1)]

    # root + single child node
    assert len(trie.children) == 1
    assert len(list(trie.all_nodes())) == 2
    assert trie.value == None

    child = trie.children[b("11")]
    assert str(child.pattern) == "1122334455667788"
    assert len(child.children) == 0
    assert child.value
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

    trie = TrieNode.new_trie()
    assert len(trie.children) == 0

    assert trie_ops.trie_insert_funcs(trie, funcs) == 2
    # 00 < 77?
    assert list(trie.all_functions()) == [node("f2", 1), node("f1", 1)]

    # root + single child node
    assert len(trie.children) == 1
    assert len(list(trie.all_nodes())) == 4

    assert list(trie.children.keys()) == [b("11")]
    c1 = trie.children[b("11")]
    assert c1.value == None
    assert str(c1.pattern) == "112233445566"
    assert list(c1.children.keys()) == [b("77"), b("00")]
    c2 = c1.children[b("77")]
    assert c2.value == [node("f1", 1)]
    assert len(list(c2.children)) == 0
    c3 = c1.children[b("00")]
    assert c3.value == [node("f2", 1)]
    assert len(list(c3.children)) == 0

    assert trie.find(bb("1122334455667788")) == [node("f1", 1)]
    assert trie.find(bb("1122334455660088")) == [node("f2", 1)]


def test_trie_find_wildcard() -> None:
    funcs = {
        node("f1"): info("??2233445566778899"),
        node("f2"): info("11??33445566778899"),
        node("f3"): info("1122??445566778899"),
    }

    trie = TrieNode.new_trie()
    assert trie_ops.trie_insert_funcs(trie, funcs) == 3

    assert trie.find(bb("112233445566778899")) == [
        node("f3", 1),
        node("f2", 1),
        node("f1", 1),
    ]
    assert trie.find(bb("992233445566778899")) == [node("f1", 1)]
    assert trie.find(bb("112299445566778899")) == [node("f3", 1)]


def test_trie_finalize() -> None:
    funcs = {
        node("f1"): info("??2233445566778899"),
        node("f2"): info("11??33445566778899"),
        node("f3"): info("1122??445566778899"),
    }

    trie = TrieNode.new_trie()
    assert trie_ops.trie_insert_funcs(trie, funcs) == 3

    trie_ops.finalize_trie(trie, funcs)
    # assert len(trie.children) == 1
