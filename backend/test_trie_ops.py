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
