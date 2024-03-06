# Copyright (c) 2015-2020 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""
Flatbuffers serialization / deserialization
"""

import zlib
import flatbuffers

from .FlatbufSignatureLibrary import CallRef as FlatBufCallRef
from .FlatbufSignatureLibrary import Function as FlatBufFunction
from .FlatbufSignatureLibrary import Pattern as FlatBufPattern
from .FlatbufSignatureLibrary import SignatureLibrary as FlatBufSignatureLibrary
from .FlatbufSignatureLibrary import TrieNode as FlatBufTrieNode

SIG_FORMAT_MAGIC = b"BNSG"
SIG_FORMAT_VERSION = 1

from .signaturelibrary import MaskedByte, Pattern, TrieNode, FunctionNode, MaskType
from typing import Optional, List, Dict, Any

FBSerialized = Any


class SignatureLibraryWriter(object):
    """
    Serializes signature libraries to a compressed Flatbuffer format usable by Binary Ninja.
    """

    def __init__(self, include_source: bool = False):
        self.builder = flatbuffers.Builder(4096)
        self.func_node_ids: Dict[Optional[FunctionNode], int] = {None: -1}
        self._bytes_cache: Dict[bytes, FBSerialized] = {}
        self._str_cache: Dict[str, FBSerialized] = {}
        self._pattern_cache: Dict[Pattern, FBSerialized] = {}
        self.include_source = include_source

    def _serialize_bytes(self, buf: bytes) -> FBSerialized:
        if buf not in self._bytes_cache:
            self._bytes_cache[buf] = self.builder.CreateByteVector(buf)
        return self._bytes_cache[buf]

    def _serialize_string(self, s: str) -> FBSerialized:
        if s not in self._str_cache:
            self._str_cache[s] = self.builder.CreateString(s)
        return self._str_cache[s]

    def _serialize_pattern_mask(self, mask: bytes) -> FBSerialized:
        mask = bytearray(mask)
        packed = bytearray((len(mask) + 7) // 8)
        for i in range(len(mask)):
            packed[i // 8] |= mask[i] << (i % 8)
        return self._serialize_bytes(bytes(packed))

    def _serialize_pattern(self, pattern: Pattern) -> FBSerialized:
        if pattern not in self._pattern_cache:
            data = self._serialize_bytes(bytes(bytearray(pattern.data())))
            mask = self._serialize_pattern_mask(bytes(bytearray(pattern.mask())))
            FlatBufPattern.PatternStart(self.builder)
            FlatBufPattern.PatternAddData(self.builder, data)
            FlatBufPattern.PatternAddMask(self.builder, mask)
            self._pattern_cache[pattern] = FlatBufPattern.PatternEnd(self.builder)
        return self._pattern_cache[pattern]

    def _serialize_func_node(self, func_node: FunctionNode) -> FBSerialized:
        func_name = self._serialize_string(func_node.name)
        if self.include_source and func_node.source_binary:
            source_binary = self._serialize_string(func_node.source_binary)
        else:
            source_binary = None

        if func_node.callees:
            FlatBufFunction.FunctionStartCalleesVector(
                self.builder, len(func_node.callees)
            )
            for call_site, callee in reversed(
                sorted(func_node.callees.items())
            ):  # this needs reversed() because we build flatbuffers by prepending
                FlatBufCallRef.CreateCallRef(
                    self.builder, call_site, self.func_node_ids[callee]
                )
            callees = self.builder.EndVector(len(func_node.callees))
        else:
            callees = None

        if func_node.pattern:
            pattern = self._serialize_pattern(func_node.pattern)
        else:
            pattern = None

        FlatBufFunction.FunctionStart(self.builder)
        if func_name:
            FlatBufFunction.FunctionAddName(self.builder, func_name)
        if source_binary:
            FlatBufFunction.FunctionAddSourceBinary(self.builder, source_binary)
        if callees:
            FlatBufFunction.FunctionAddCallees(self.builder, callees)
        if func_node.is_bridge:
            FlatBufFunction.FunctionAddIsBridge(self.builder, func_node.is_bridge)
        if pattern:
            FlatBufFunction.FunctionAddPattern(self.builder, pattern)
            FlatBufFunction.FunctionAddPatternOffset(
                self.builder, func_node.pattern_offset
            )
        return FlatBufFunction.FunctionEnd(self.builder)

    def _serialize_trie_node(
        self, trie_node: TrieNode, key: Optional[int] = None
    ) -> FBSerialized:
        pattern = self._serialize_pattern(trie_node.pattern)
        if trie_node.children:
            children_offs = [
                self._serialize_trie_node(v, k.value)
                for k, v in sorted(trie_node.children.items())
                if k != MaskedByte.wildcard()
            ]
            FlatBufTrieNode.TrieNodeStartChildrenVector(
                self.builder, len(children_offs)
            )
            for off in reversed(
                children_offs
            ):  # this needs reversed() because we build flatbuffers by prepending
                self.builder.PrependUOffsetTRelative(off)
            children = self.builder.EndVector(len(children_offs))
            if MaskedByte.wildcard() in trie_node.children:
                wildcard_child = self._serialize_trie_node(
                    trie_node.children[MaskedByte.wildcard()]
                )
            else:
                wildcard_child = None
        else:
            wildcard_child = None
            children = None
        if trie_node.value:
            FlatBufTrieNode.TrieNodeStartFunctionsVector(
                self.builder, len(trie_node.value)
            )
            for f in reversed(
                trie_node.value
            ):  # this needs reversed() because we build flatbuffers by prepending
                self.builder.PrependUint32(self.func_node_ids[f])
            functions = self.builder.EndVector(len(trie_node.value))
        else:
            functions = None

        FlatBufTrieNode.TrieNodeStart(self.builder)
        if key is not None:  # what about duplicate between 0 and wildcard...?
            assert type(key) == int and 0 <= key <= 255
            assert trie_node.pattern[0].mask == 1 and key == trie_node.pattern[0].value
            FlatBufTrieNode.TrieNodeAddPatternPrefix(self.builder, key)
        FlatBufTrieNode.TrieNodeAddPattern(self.builder, pattern)
        if children:
            FlatBufTrieNode.TrieNodeAddChildren(self.builder, children)
        if wildcard_child:
            FlatBufTrieNode.TrieNodeAddWildcardChild(self.builder, wildcard_child)
        if functions:
            FlatBufTrieNode.TrieNodeAddFunctions(self.builder, functions)
        return FlatBufTrieNode.TrieNodeEnd(self.builder)

    def serialize(self, sig_trie: TrieNode) -> bytes:
        """
        Creates a new Flatbuffer and serializes the specified signature trie to it.
        Returns a binary signature library ready for use with Binary Ninja.
        :param sig_trie: `TrieNode` object
        :return: bytes-like object
        """
        # Enforce ordering to make the traversal order consistent
        for n in sig_trie.all_nodes():
            if n.value:
                n.value = list(
                    sorted(
                        n.value,
                        key=lambda func_node: func_node.source_binary
                        + "!"
                        + func_node.name,
                    )
                )

        func_nodes: List[FunctionNode] = []

        def visit(func_node: Optional[FunctionNode]) -> None:
            if not func_node:
                return
            if func_node in self.func_node_ids:
                return
            self.func_node_ids[func_node] = len(func_nodes)
            func_nodes.append(func_node)
            for k, f in sorted(func_node.callees.items()):
                visit(f)

        for f in sig_trie.all_values():
            visit(f)

        func_nodes = [
            self._serialize_func_node(f) for f in reversed(func_nodes)
        ]  # this needs reversed() because we build flatbuffers by prepending
        FlatBufSignatureLibrary.SignatureLibraryStartFunctionsVector(
            self.builder, len(func_nodes)
        )
        for off in func_nodes:
            self.builder.PrependUOffsetTRelative(off)
        functions = self.builder.EndVector(len(func_nodes))

        root = self._serialize_trie_node(sig_trie)

        FlatBufSignatureLibrary.SignatureLibraryStart(self.builder)
        FlatBufSignatureLibrary.SignatureLibraryAddFunctions(self.builder, functions)
        FlatBufSignatureLibrary.SignatureLibraryAddRoot(self.builder, root)
        off = FlatBufSignatureLibrary.SignatureLibraryEnd(self.builder)
        self.builder.Finish(off)

        return (
            SIG_FORMAT_MAGIC
            + bytes(bytearray([SIG_FORMAT_VERSION]))
            + zlib.compress(bytes(self.builder.Output()))
        )


class SignatureLibraryReader(object):
    """
    Parses and loads compressed Flatbuffer signature libraries.
    """

    def __init__(self) -> None:
        self.funcs: List[FunctionNode] = []

    def _deserialize_pattern(self, serialized: FBSerialized) -> Pattern:
        # we cannot use DataAsNumpy as we don't depend on numpy
        data = bytes(
            bytearray([serialized.Data(i) for i in range(serialized.DataLength())])
        )

        mask = []
        for i in range(serialized.MaskLength()):
            b = serialized.Mask(i)
            for j in range(8):
                mask.append((b >> j) & 1)
                if len(mask) == len(data):
                    break

        return Pattern(data, mask)

    def _deserialize_func_node(self, serialized: FBSerialized) -> FunctionNode:
        func_node = FunctionNode(serialized.Name().decode("utf-8"))
        if serialized.SourceBinary():
            func_node.source_binary = serialized.SourceBinary().decode("utf-8")
        # func_node.is_bridge = serialized.IsBridge()
        if serialized.Pattern():
            func_node.pattern = self._deserialize_pattern(serialized.Pattern())
            func_node.pattern_offset = serialized.PatternOffset()
        return func_node

    def _deserialize_trie_node(self, serialized: FBSerialized) -> TrieNode:
        children = {}
        prev = float("-inf")
        for i in range(serialized.ChildrenLength()):
            child = serialized.Children(i)
            children[
                MaskedByte.new(child.PatternPrefix(), 1)
            ] = self._deserialize_trie_node(child)
            assert child.PatternPrefix() >= prev  # assert sorted
            prev = child.PatternPrefix()
        wildcard = serialized.WildcardChild()
        if wildcard:
            children[MaskedByte.wildcard()] = self._deserialize_trie_node(wildcard)
        funcs = []
        for i in range(serialized.FunctionsLength()):
            funcs.append(self.funcs[serialized.Functions(i)])
        pattern = self._deserialize_pattern(serialized.Pattern())
        return TrieNode(pattern, children, funcs)

    def deserialize(self, buf: bytes) -> TrieNode:
        """
        Loads a signature library from an in-memory buffer.
        This implementation is extremely inefficient! Use it for debugging and signature library generation only.
        :param buf: bytes-like object
        :return: root `TrieNode` of the signature library
        """
        if buf[0:4] != b"BNSG":
            raise RuntimeError("invalid signature library magic")
        if ord(buf[4:5]) != SIG_FORMAT_VERSION:
            raise RuntimeError(
                "signature version mismatch: got %d, expected %d"
                % (ord(buf[4:5]), SIG_FORMAT_VERSION)
            )
        buf = zlib.decompress(buf[5:])
        serialized = FlatBufSignatureLibrary.GetRootAsSignatureLibrary(buf, 0)  # type: ignore
        funcs_serialized = []
        for i in range(serialized.FunctionsLength()):
            f = serialized.Functions(i)
            funcs_serialized.append(f)
            self.funcs.append(self._deserialize_func_node(f))
        for i, f in enumerate(funcs_serialized):  # link callgraph
            callees = {}
            prev = float("-inf")
            for j in range(f.CalleesLength()):
                callsite = f.Callees(j)
                callees[callsite.Offset()] = (
                    None if callsite.DstId() == -1 else self.funcs[callsite.DstId()]
                )
                assert callsite.Offset() >= prev  # assert sorted
                prev = callsite.Offset()
            self.funcs[i].callees = callees

        trie = self._deserialize_trie_node(serialized.Root())
        for func in trie.all_values():  # recalculate refcounts
            func.ref_count += 1
        return trie


def dumps(sig_trie: TrieNode, **kwargs):  # type: ignore
    return SignatureLibraryWriter(**kwargs).serialize(sig_trie)


def dump(sig_trie: TrieNode, fp, **kwargs) -> None:  # type: ignore
    fp.write(dumps(sig_trie, **kwargs))


def loads(serialized):  # type: ignore
    return SignatureLibraryReader().deserialize(serialized)


def load(fp):  # type: ignore
    return loads(fp.read())
