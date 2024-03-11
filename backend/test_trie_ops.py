from pprint import pprint
from . import trie_ops
from .binja_api import SymbolType as ST

from .test_trie_util import node, info, p, b, bb


def test_resolve_reference() -> None:
    r = trie_ops.resolve_reference
    assert r("foo", ST.FunctionSymbol, "binary", {}) == None
    assert r("foo", ST.FunctionSymbol, "binary", {"binary_wrong": node("f1")}) == None
    assert r("foo", ST.FunctionSymbol, "binary", {"binary": node("f1")}) == node("f1")

    assert r("foo", ST.DataSymbol, "binary", {}) == None
    assert r("foo", ST.DataSymbol, "binary", {"binary": node("f1")}) == None
    assert r("foo", ST.DataSymbol, "binary", {"binary_wrong": node("f1")}) == node("f1")
    assert (
        r(
            "foo",
            ST.DataSymbol,
            "binary",
            {"binary_wrong1": node("f1"), "binary_wrong2": node("f2")},
        )
        == None
    )


def test_link_callgraph() -> None:
    # should add callee to node
    funcs = {
        node("f1", 0, "bin1"): info("11", {0: ("f2", ST.FunctionSymbol)}),
        node("f2", 0, "bin1"): info("22"),
    }
    trie_ops.link_callgraph(funcs)
    items = list(funcs.items())
    first_key = items[0][0]
    assert first_key.name == "f1"
    assert first_key.callees == {0: node("f2", 0, "bin1")}

    # preserve external symbols, if present
    funcs = {
        node("f1", 0, "bin1"): info("11", {0: ("f2", ST.ExternalSymbol)}),
        node("f2", 0, "bin2"): info("22"),
    }
    trie_ops.link_callgraph(funcs)
    items = list(funcs.items())
    first_key = items[0][0]
    assert first_key.name == "f1"
    assert first_key.callees == {0: node("f2", 0, "bin2")}

    # preserve negative offset-callees in same binary
    funcs = {
        node("f1", 0, "bin1"): info("11", {-100: ("f2", ST.FunctionSymbol)}),
        node("f2", 0, "bin1"): info("22"),
    }
    trie_ops.link_callgraph(funcs)
    items = list(funcs.items())
    first_key = items[0][0]
    assert first_key.name == "f1"
    assert first_key.callees == {-100: node("f2", 0, "bin1")}

    # "f1" is in different binary, hence None
    funcs = {
        node("f1", 0, "bin1"): info("11", {0: ("f2", ST.FunctionSymbol)}),
        node("f2", 0, "bin2"): info("22"),
    }
    trie_ops.link_callgraph(funcs)
    items = list(funcs.items())
    first_key = items[0][0]
    assert first_key.name == "f1"
    assert first_key.callees == {0: None}

    # "f2" call is outside the pattern, hence None
    funcs = {
        node("f1", 0, "bin1"): info("", {0: ("f2", ST.FunctionSymbol)}),
        node("f2", 0, "bin1"): info("22"),
    }
    trie_ops.link_callgraph(funcs)
    items = list(funcs.items())
    first_key = items[0][0]
    assert first_key.name == "f1"
    assert first_key.callees == {0: None}

    # "f2" call is on a wildcard, hence None
    funcs = {
        node("f1", 0, "bin1"): info("??", {0: ("f2", ST.FunctionSymbol)}),
        node("f2", 0, "bin1"): info("22"),
    }
    trie_ops.link_callgraph(funcs)
    items = list(funcs.items())
    first_key = items[0][0]
    assert first_key.name == "f1"
    assert first_key.callees == {0: None}
