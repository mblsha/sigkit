from .sig_match import SignatureMatcher

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
from typing import Dict, List, Optional


class MockBasicBlock:
    def __init__(self, start: int, end: int) -> None:
        self.start = start
        self.end = end

    @property
    def has_invalid_instructions(self) -> bool:
        return False


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


class MockFunction:
    def __init__(self, view: "MockBinaryView", name: str, data: bytes) -> None:
        self._view = view
        self._name = name
        self._data = data
        self._basic_blocks: List[MockBasicBlock] = []
        self.mlil: List[MockMLIL] = []

    @property
    def view(self) -> "MockBinaryView":
        return self._view

    @property
    def name(self) -> str:
        return self._name

    @property
    def start(self) -> int:
        return self._basic_blocks[0].start

    @property
    def basic_blocks(self) -> list[MockBasicBlock]:
        return self._basic_blocks


class MockBinaryView:
    def __init__(self) -> None:
        self._data = b""
        self._functions: List[MockFunction] = []
        self._functions_at: Dict[int, MockFunction] = {}

    def add_function(self, f: MockFunction) -> None:
        self._functions.append(f)
        start = len(self._data)
        self._data += f._data
        end = len(self._data)
        f._basic_blocks.append(MockBasicBlock(start, end))
        self._functions_at[start] = f

    @property
    def functions(self) -> list[MockFunction]:
        return self._functions

    def get_function_at(self, addr: int) -> Optional[MockFunction]:
        return self._functions_at.get(addr)

    def read(self, addr: int, length: int) -> bytes:
        return b"\x00" * length

    @property
    def end(self) -> int:
        return len(self._data) + 0x1000


def test_resolve_thunk_not_thunk() -> None:
    bv = MockBinaryView()
    f1 = MockFunction(bv, "f1", bb("1122334455667788"))
    bv.add_function(f1)

    trie = TrieNode.new_trie()
    matcher = SignatureMatcher(trie, bv)

    assert matcher.resolve_thunk(f1) == f1
    assert get_func_len(f1) == len(f1._data)


def test_resolve_thunk_tailcall_recursion() -> None:
    bv = MockBinaryView()
    f1 = MockFunction(bv, "f1", bb("11223344"))
    f1.mlil = [MockMLIL(MediumLevelILOperation.MLIL_TAILCALL, dest=value_value(0))]
    bv.add_function(f1)

    trie = TrieNode.new_trie()
    matcher = SignatureMatcher(trie, bv)

    assert matcher.resolve_thunk(f1) == None

def test_resolve_thunk_tailcall_to_unknown() -> None:
    bv = MockBinaryView()
    f1 = MockFunction(bv, "f1", bb("11223344"))
    f1.mlil = [MockMLIL(MediumLevelILOperation.MLIL_TAILCALL,
                        dest=value_value(1000))]
    bv.add_function(f1)

    trie = TrieNode.new_trie()
    matcher = SignatureMatcher(trie, bv)

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
    f2.mlil = [
        MockMLIL(MediumLevelILOperation.MLIL_CONST_PTR, dest=value_value(0))
    ]
    bv.add_function(f2)
    assert get_bb_len(f2.basic_blocks[0]) == len(f2._data)
    assert get_func_len(f2) == len(f2._data)

    trie = TrieNode.new_trie()
    matcher = SignatureMatcher(trie, bv)

    assert matcher.resolve_thunk(f1) == f2


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
    assert len(matcher._matches) == 0
