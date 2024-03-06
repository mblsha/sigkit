from pprint import pprint

from . import sig_serialize_json as sjson
from . import sig_serialize_fb as sfb
from .signaturelibrary import FunctionNode, TrieNode, Pattern, MaskedByte

from . import signaturelibrary as sl
from .test_trie_util import node, info, p, b, bb
from . import trie_ops


def test_serialize_bytes() -> None:
    writer = sfb.SignatureLibraryWriter()
    r1 = writer._serialize_bytes(b"\x12\x34")
    assert r1 == 8

    r2 = writer._serialize_bytes(b"\x12\x34")
    assert r2 == r1

    r3 = writer._serialize_bytes(b"\x00\x34")
    assert r3 != r1


def test_serialize_string() -> None:
    writer = sfb.SignatureLibraryWriter()
    r1 = writer._serialize_string("te")
    assert r1 == 8

    r2 = writer._serialize_string("te")
    assert r2 == r1

    r3 = writer._serialize_string("test2")
    assert r3 != r1


def test_serialize_pattern_mask() -> None:
    writer = sfb.SignatureLibraryWriter()
    r1 = writer._serialize_pattern_mask(b"\x01\x00")
    assert r1 == 8

    r2 = writer._serialize_pattern_mask(b"\x01\x00")
    assert r2 == r1

    r3 = writer._serialize_pattern_mask(b"\x00\x00")
    assert r3 != r1


def test_serialize_trie_node() -> None:
    funcs = {
        node("f1"): info("??2233445566778899"),
        node("f2"): info("11??33445566778899"),
        node("f3"): info("1122??445566778899"),
    }

    trie = TrieNode.new_trie()
    assert trie_ops.trie_insert_funcs(trie, funcs) == 3

    writer = sfb.SignatureLibraryWriter()
    r = writer.serialize(trie)

    reader = sfb.SignatureLibraryReader()
    trie2 = reader.deserialize(r)
    print(trie)
    print(trie2)
    assert trie2 == trie
