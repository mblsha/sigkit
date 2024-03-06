from pprint import pprint

from . import sig_serialize_json as sjson
from .signaturelibrary import FunctionNode, TrieNode, Pattern, MaskedByte

from . import signaturelibrary as sl
from .test_trie_util import node, info, p, b, bb
from . import trie_ops


def test_get_func_nodes() -> None:
    f1 = FunctionNode("f1")
    r = sjson.get_func_nodes([f1])
    assert r.func_nodes == [f1]
    assert r.func_node_ids == {None: -1, f1: 0}

    f2 = FunctionNode("f2")
    r = sjson.get_func_nodes([f1, f2])
    assert r.func_nodes == [f1, f2]
    assert r.func_node_ids == {None: -1, f1: 0, f2: 1}

    f3 = FunctionNode("f3")
    f3.callees = {0x10: f1}
    r = sjson.get_func_nodes([f3])
    assert r.func_nodes == [f3, f1]
    assert r.func_node_ids == {None: -1, f3: 0, f1: 1}


def test_serialize_func_node() -> None:
    f = FunctionNode("test", "binary")
    f.pattern = Pattern.from_str("??34")
    f.pattern_offset = 0x10
    f.callees = {0x20: FunctionNode("callee")}

    func_nodes, func_node_ids = sjson.get_func_nodes([f])
    assert func_node_ids[FunctionNode("callee")] == 1

    r = sjson._serialize_func_node(f, func_node_ids)
    assert r == {
        "name": "test",
        "source_binary": "binary",
        "pattern": "??34",
        "pattern_offset": 0x10,
        "callees": {"32": 1},
    }

    assert sjson._deserialize_func_node(r) == f


def test_serialize_trie_node() -> None:
    funcs = {
        node("f1"): info("??2233445566778899"),
        node("f2"): info("11??33445566778899"),
        node("f3"): info("1122??445566778899"),
    }

    trie = TrieNode.new_trie()
    assert trie_ops.trie_insert_funcs(trie, funcs) == 3

    r = sjson.serialize(trie)
    pprint(r)
    assert r == {
        "functions": [
            {
                "callees": {},
                "name": "f3",
                "pattern": "",
                "pattern_offset": 0,
                "source_binary": "",
            },
            {
                "callees": {},
                "name": "f2",
                "pattern": "",
                "pattern_offset": 0,
                "source_binary": "",
            },
            {
                "callees": {},
                "name": "f1",
                "pattern": "",
                "pattern_offset": 0,
                "source_binary": "",
            },
        ],
        "trie": {
            "children": {
                "11": {
                    "children": {
                        "22": {
                            "children": {},
                            "functions": [0],
                            "pattern": "22??445566778899",
                        },
                        "??": {
                            "children": {},
                            "functions": [1],
                            "pattern": "??33445566778899",
                        },
                    },
                    "functions": [],
                    "pattern": "11",
                },
                "??": {
                    "children": {},
                    "functions": [2],
                    "pattern": "??2233445566778899",
                },
            },
            "functions": [],
            "pattern": "",
        },
    }

    trie2 = sjson.deserialize(r)
    print(trie)
    print(trie2)
    assert trie2 == trie
