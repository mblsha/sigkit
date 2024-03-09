from .sig_match import SignatureMatcher, MatchResult

from ..backend.signaturelibrary import (
    FunctionInfo,
    FunctionNode,
    TrieNode,
)

from ..backend.test_trie_util import node, info, p, b, bb
from ..backend import trie_ops
from ..sigkit.compute_sig import get_func_len, get_bb_len

from ..backend import binja_api
from binaryninja import (
    MediumLevelILInstruction,
    MediumLevelILOperation,
)

from unittest.mock import MagicMock, Mock, PropertyMock
from typing import Dict, List, Optional, Any


class MockBasicBlock:
    def __init__(self, start: int, end: int) -> None:
        self.start = start
        self.end = end
        self.has_invalid_instructions = False


def value_value(value: int) -> MagicMock:
    v = MagicMock()
    v.value = MagicMock()
    v.value.value = value
    return v


class MockMLIL:
    def __init__(
        self,
        op: MediumLevelILOperation,
        src: Optional[MagicMock] = None,
        dest: Optional[MagicMock] = None,
    ) -> None:
        self.operation = op
        self.src = src
        self.dest = dest


class MockCallSite:
    def __init__(
        self,
        bv: "MockBinaryView",
        address: int,
        func: Optional["MockFunction"] = None,
        arch: Optional[str] = None,
    ) -> None:
        self._view = bv
        self.address = address
        self.function = func
        self.arch = arch


class MockFunction:
    def __init__(self, view: "MockBinaryView", name: str, data: bytes) -> None:
        self.view = view
        self.name = name
        self._data = data
        self.basic_blocks: List[MockBasicBlock] = []
        self.mlil: List[MockMLIL] = []
        self.call_sites: List[MockCallSite] = []

    @property
    def start(self) -> int:
        return self.basic_blocks[0].start


class MockBinaryView:
    def __init__(self) -> None:
        self._data = b""
        self._functions: List[MockFunction] = []
        self._functions_at: Dict[int, MockFunction] = {}
        self._callees_at: Dict[int, List[int]] = {}

    def add_function(self, f: MockFunction) -> None:
        self._functions.append(f)
        start = len(self._data)
        self._data += f._data
        end = len(self._data)
        f.basic_blocks.append(MockBasicBlock(start, end))
        self._functions_at[start] = f

    @property
    def functions(self) -> list[MockFunction]:
        return self._functions

    def get_function_at(self, addr: int) -> Optional[MockFunction]:
        return self._functions_at.get(addr)

    def get_callees(
        self, addr: int, func: Optional[MockFunction], arch: Optional[str]
    ) -> List[int]:
        return self._callees_at[addr]

    def read(self, addr: int, length: int) -> bytes:
        return self._data[addr : addr + length]

    @property
    def end(self) -> int:
        return len(self._data) + 0x1000


def test_resolve_thunk_not_thunk() -> None:
    bv = MockBinaryView()
    f1 = MockFunction(bv, "f1", bb("1122334455667788"))
    bv.add_function(f1)

    matcher = SignatureMatcher(TrieNode.new_trie(), bv)

    assert matcher.resolve_thunk(f1) == f1
    assert get_func_len(f1) == len(f1._data)


def test_resolve_thunk_tailcall_recursion() -> None:
    bv = MockBinaryView()
    f1 = MockFunction(bv, "f1", bb("11223344"))
    f1.mlil = [MockMLIL(MediumLevelILOperation.MLIL_TAILCALL, dest=value_value(0))]
    bv.add_function(f1)

    matcher = SignatureMatcher(TrieNode.new_trie(), bv)

    assert matcher.resolve_thunk(f1) == None


def test_resolve_thunk_tailcall_to_unknown() -> None:
    bv = MockBinaryView()
    f1 = MockFunction(bv, "f1", bb("11223344"))
    f1.mlil = [MockMLIL(MediumLevelILOperation.MLIL_TAILCALL, dest=value_value(1000))]
    bv.add_function(f1)

    matcher = SignatureMatcher(TrieNode.new_trie(), bv)

    assert matcher.resolve_thunk(f1) == None


def test_resolve_thunk_tailcall() -> None:
    bv = MockBinaryView()
    f1 = MockFunction(bv, "f1", bb("11223344"))
    f1.mlil = [
        MockMLIL(MediumLevelILOperation.MLIL_TAILCALL, dest=value_value(len(f1._data)))
    ]
    bv.add_function(f1)
    assert get_bb_len(f1.basic_blocks[0]) == len(f1._data)
    assert get_func_len(f1) == len(f1._data)

    f2 = MockFunction(bv, "f2", bb("11223344"))
    f2.mlil = [MockMLIL(MediumLevelILOperation.MLIL_CONST_PTR, dest=value_value(0))]
    bv.add_function(f2)
    assert get_bb_len(f2.basic_blocks[0]) == len(f2._data)
    assert get_func_len(f2) == len(f2._data)

    matcher = SignatureMatcher(TrieNode.new_trie(), bv)

    assert matcher.resolve_thunk(f1) == f2


def test_resolve_thunk_jump() -> None:
    # FIXME
    pass


def test_on_match() -> None:
    funcs = {
        node("f1"): info("??2233445566778899"),
        node("f2"): info("11??33445566778899"),
        node("f3"): info("1122??445566778899"),
    }

    trie = TrieNode.new_trie()
    assert trie_ops.trie_insert_funcs(trie, funcs) == 3

    bv = MockBinaryView()
    f1 = MockFunction(bv, "f1", bb("112233445566778899"))
    bv.add_function(f1)

    matcher = SignatureMatcher(trie, bv)

    matcher.on_match(f1, node("f1"))
    assert matcher.results == {f1: node("f1")}

    # conflict
    matcher.on_match(f1, node("f2"))
    assert matcher.results == {}

    matcher.on_match(f1, node("f1"))
    assert matcher.results == {}

    matcher.on_match(f1, node("f2"))
    assert matcher.results == {}

    # reset matcher, try with another wildcard
    matcher = SignatureMatcher(trie, bv)
    matcher.on_match(f1, node("f2"))
    assert matcher.results == {f1: node("f2")}


def test_compute_func_callees() -> None:
    bv = MockBinaryView()
    f1 = MockFunction(bv, "f1", bb("112233445566778899"))
    bv.add_function(f1)

    matcher = SignatureMatcher(TrieNode.new_trie(), bv)
    assert matcher.compute_func_callees(f1) == {}

    f1.call_sites.append(MockCallSite(bv, 1000, f1))
    bv._callees_at[1000] = [f1.start]
    assert matcher.compute_func_callees(f1) == {1000: f1}


def test_does_func_match() -> None:
    node_f1_disambiguation1 = node("f1d", 1, p("9922"), 0)
    node_f1_disambiguation2 = node("f1d", 1, p("1122"), 0)
    funcs = {
        node("f1"): info("??2233445566778899"),
        node("f2"): info("11??33445566778899"),
        node("f3"): info("1122??445566778899"),
        node_f1_disambiguation1: info("1122??445566778899"),
        node_f1_disambiguation2: info("1122??445566778899"),
    }

    trie = TrieNode.new_trie()
    assert trie_ops.trie_insert_funcs(trie, funcs) == 5

    bv = MockBinaryView()
    f1 = MockFunction(bv, "f1", bb("112233445566778899"))
    bv.add_function(f1)
    f2 = MockFunction(bv, "f2", bb("998877665544332211"))
    bv.add_function(f2)

    def match(*args: Any) -> MatchResult:
        matcher = SignatureMatcher(trie, bv)
        return matcher.does_func_match(*args)

    # visited: Dict[MockFunction, FunctionNode] = {}

    # no funcion -> no match
    assert match(None, node("f1", 1), {}) == MatchResult.NO_MATCH
    assert match(None, node("f1", 0), {}) == MatchResult.NO_MATCH
    assert match(None, None, {}) == MatchResult.NO_MATCH

    # wildcard full match
    assert match(f1, None, {}) == MatchResult.FULL_MATCH

    # f99 is a bridge node, they skip the trie check
    assert match(f1, node("f99", 0), {}) == MatchResult.FULL_MATCH

    # full match
    assert match(f1, node("f1", 1), {}) == MatchResult.FULL_MATCH
    assert match(f1, node("f2", 1), {}) == MatchResult.FULL_MATCH
    assert match(f1, node("f3", 1), {}) == MatchResult.FULL_MATCH

    # trie mismatch
    assert match(f2, node("f1", 1), {}) == MatchResult.NO_MATCH
    assert match(f2, node("f2", 1), {}) == MatchResult.NO_MATCH
    assert match(f2, node("f3", 1), {}) == MatchResult.NO_MATCH

    # visited match
    assert match(f2, node("f1", 1), {f2: node("f1", 1)}) == MatchResult.FULL_MATCH

    # cached _matches influences the result
    if True:
        matcher = SignatureMatcher(trie, bv)
        matcher._matches[f2] = node("f1", 1)
        assert matcher.does_func_match(f2, node("f1", 1), {}) == MatchResult.FULL_MATCH

        matcher._matches[f2] = node("f2", 1)
        assert matcher.does_func_match(f2, node("f1", 1), {}) == MatchResult.NO_MATCH

    # disambiguation
    assert match(f1, node_f1_disambiguation1, {}) == MatchResult.DISAMBIGUATION_MISMATCH
    assert match(f1, node_f1_disambiguation2, {}) == MatchResult.FULL_MATCH

    # callees
    # TODO


def test_signature_matcher() -> None:
    funcs = {
        node("f1"): info("??2233445566778899"),
        node("f2"): info("11??33445566778899"),
        node("f3"): info("1122??445566778899"),
    }

    trie = TrieNode.new_trie()
    assert trie_ops.trie_insert_funcs(trie, funcs) == 3

    bv = MockBinaryView()
    bv.add_function(MockFunction(bv, "f1", bb("112233445566778899")))

    matcher = SignatureMatcher(trie, bv)
    assert matcher.run_pass(bv.functions) == []
    assert len(matcher._matches) == 1
