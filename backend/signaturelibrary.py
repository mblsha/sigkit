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
This package contains definitions for the data structures and objects used in
Signature Libraries. To construct a new empty signature trie, use `new_trie`.
"""

import sys
import functools
from itertools import starmap

from typing import (
    Dict,
    List,
    Optional,
    Literal,
    Union,
    cast,
    Generator,
    Any,
    Set,
    Iterator,
)
from dataclasses import dataclass, field

MaskType = Literal[0, 1]
MIN_PATTERN_LENGTH = 8

@functools.total_ordering  # for sorted()
class MaskedByte(object):
    """
    Represents a pattern to match a single byte: either a value from 0-255, or a wildcard, '??'
    Algebraically, you can imagine that there is a partial ordering where 0-255 < ??, or
    alternatively, a total ordering where 0 < 1 < 2 < ... < 255 < ??

    This class is backed by a flyweight cache. Use `MaskedByte.new` to construct.
    """

    _wildcard: Optional["MaskedByte"] = None
    _cache: Dict[int, "MaskedByte"] = {}

    def __init__(self, value: int, mask: MaskType):
        assert type(value) == int
        self._value = value
        self._mask = mask

    @staticmethod
    def wildcard() -> "MaskedByte":
        if MaskedByte._wildcard is None:
            MaskedByte._wildcard = MaskedByte(0, 0)
        return MaskedByte._wildcard

    @property
    def value(self) -> int:
        return self._value

    @property
    def mask(self) -> MaskType:
        return self._mask

    @staticmethod
    def new(value: int, mask: MaskType) -> "MaskedByte":
        assert type(value) == int
        assert 0 <= value <= 255
        if mask == 0:
            return MaskedByte.wildcard()
        else:
            if not value in MaskedByte._cache:
                MaskedByte._cache[value] = MaskedByte(value, mask)
            return MaskedByte._cache[value]

    @staticmethod
    def from_str(s: str) -> "MaskedByte":
        assert len(s) == 2
        if s == "??":
            return MaskedByte.wildcard()
        else:
            return MaskedByte.new(int(s, 16), 1)

    def __str__(self) -> str:
        return "%02x" % (self._value,) if self._mask == 1 else "??"

    def __repr__(self) -> str:
        return f"<{self.__str__()}>"

    def __eq__(self, other: object) -> bool:
        if not type(other) == type(self):
            return False
        other = cast(MaskedByte, other)
        return self.matches(other) and other.matches(self)

    # this defines a total ordering
    def __hash__(self) -> int:
        if self._mask == 0:
            return 256
        else:
            return self._value  # 0-255

    # this is only here for sorting purposes in python, no fancy algebraic interpretation behind it.
    def __le__(self, other: "MaskedByte") -> bool:
        return self.__hash__() <= other.__hash__()

    def matches(self, other: Union["MaskedByte", int]) -> bool:
        """
        Defines a *partial* ordering, essentially a >= operator algebraically:
        (00...FF) <= ??; other elements are incomparable.
        :param other: MaskedByte or byte
        :return: True if all bytes matched by `other` are also matched by this
        """
        if self._mask == 0:
            return True
        if isinstance(other, MaskedByte):
            if other._mask == 0:
                return False
            else:
                return self._value == other._value
        assert type(other) == int
        return self._value == other

    # Meet operator
    def intersect(self, other: "MaskedByte") -> Optional["MaskedByte"]:
        if self._mask == 0 and other._mask == 0:
            return MaskedByte.wildcard()
        elif self._mask == 0 and other._mask == 1:
            return other
        elif self._mask == 1 and other._mask == 0:
            return self
        elif self._value == other._value:
            return self
        else:
            return None  # NO intersection!

    # Join operator
    def union(self, other: "MaskedByte") -> "MaskedByte":
        if self._mask == 0 or other._mask == 0:
            return MaskedByte.wildcard()
        elif self._value == other._value:
            return self
        else:
            return MaskedByte.wildcard()  # !!


class Pattern:
    """
    Represents a pattern used for matching byte sequences; a sequence of MaskedByte.
    For example, the string representation of a Pattern looks like `1234??56??78` .
    Behaves like an array.
    """

    def __init__(self, data: bytes, mask: List[MaskType]):
        """
        Constructs a new pattern object
        :param data: bytes-like object, byte sequence of this pattern.
        :param mask: wildcard mask for the pattern. must be the same length as `data`. array of 0 or 1, 0 means wildcard at that position
        :return:
        """
        assert len(data) == len(mask)
        for elem in mask:
            assert elem == 0 or elem == 1
        # FIXME: is this array of MaskedByte?
        self._array = tuple(
            MaskedByte.new((data[i]), mask[i]) for i in range(len(data))
        )

    @staticmethod
    def from_str(s: str) -> "Pattern":
        if len(s) % 2:
            raise ValueError("odd pattern length " + str(len(s)) + ": " + s)
        p = Pattern(b"", [])
        p._array = tuple(MaskedByte.from_str(s[i : i + 2]) for i in range(0, len(s), 2))
        return p

    def __str__(self) -> str:
        return "".join(map(str, self._array))

    def slice(self, item: slice) -> "Pattern":
        assert isinstance(item, slice)
        p = Pattern(b"", [])
        p._array = self._array.__getitem__(item)
        return p

    def __getitem__(self, item: int) -> MaskedByte:
        return self._array.__getitem__(item)

    def __len__(self) -> int:
        return self._array.__len__()

    def __iter__(self) -> Iterator[MaskedByte]:
        return self._array.__iter__()

    def __eq__(self, other: object) -> bool:
        if not type(other) == type(self):
            return False
        other = cast(Pattern, other)
        return self._array.__eq__(other._array)

    def __hash__(self) -> int:
        return self._array.__hash__()

    def matches(self, buf: "Pattern") -> bool:
        """
        Checks if this Pattern matches `buf`.
        :param buf: Pattern or bytestring
        :return: True if all bytes matched by `other` are also matched by this
        """
        if len(self._array) > len(buf):
            return False
        return all(starmap(MaskedByte.matches, zip(self._array, buf)))

    # Meet operator
    def intersect(self, other: "Pattern") -> Optional["Pattern"]:
        # right-pad with wildcard
        size = max(len(self._array), len(other._array))
        array1 = self._array + tuple(
            [MaskedByte.wildcard()] * (size - len(self._array))
        )
        array2 = other._array + tuple(
            [MaskedByte.wildcard()] * (size - len(other._array))
        )
        result_array = tuple(starmap(MaskedByte.intersect, zip(array1, array2)))
        if not all(result_array):
            return None
        p = Pattern(b"", [])
        p._array = result_array  # type: ignore
        return p

    # Join operator
    def union(self, other: "Pattern") -> "Pattern":
        # length truncated to smallest
        result_array = tuple(starmap(MaskedByte.union, zip(self._array, other._array)))
        p = Pattern(b"", [])
        p._array = result_array
        return p

    def data(self) -> Generator[int, None, None]:
        for b in self._array:
            yield b.value

    def mask(self) -> Generator[MaskType, None, None]:
        for b in self._array:
            yield b.mask


def empty_pattern() -> Pattern:
    return Pattern(b"", [])


@dataclass
class FunctionInfo:
    """
    Stores additional information about functions that are useful while generating and manipulating
    signature libraries, but excluded from the finalized signature library to save space.
    This information is also used to simulate linking when generating the call-graph.
    """

    # list of `Pattern`s which match this function
    patterns: List[Pattern] = field(default_factory=list)

    # dictionary of {offset: (destination name, `ReferenceType`)}; other symbols this function calls
    callees: Dict[int, str] = field(default_factory=dict)

    # list of string containing other possible names that could link to this function
    aliases: List[str] = field(default_factory=list)


@dataclass
class FunctionNode(object):
    """
    Represents a function that we would like to match and contains relevant metadata for matching purposes.
    Function nodes are connected with each other by a call graph. This helps not only encode information about
    individual functions but also the relationships between them when matching.
    Each FunctionNode is a vertex of the call graph, represented by an edge list stored in `callees`.

    To create a FunctionNode for a given function, see `compute_sig.process_function`.
    """

    # The name of the matched function
    name: str

    # The filename of the binary that the function came from (malloc.o for example). Optional.
    source_binary: str = ""

    # used to disambiguate when multiple FunctionNodes are matched
    pattern: Pattern = field(default_factory=empty_pattern)
    pattern_offset: int = 0

    # Forms a callgraph with other `FunctionNodes`.
    # Dict of {call_offset: destination}.
    callees: Dict[int, "FunctionNode"] = field(default_factory=dict)

    # Number of places this node is in its signature trie
    ref_count: int = 0

    def __hash__(self) -> int:
        return hash((self.name, self.source_binary))

    @property
    def is_bridge(self):
        return self.ref_count == 0

    def __str__(self):
        return "<func:" + self.name + ":" + self.source_binary + ">"

    def __repr__(self):
        result = "<func:"
        result += str(self.ref_count) + " "
        result += self.name + ":" + self.source_binary
        if self.callees:
            result += (
                ":{"
                + ", ".join(
                    map(
                        lambda k: str(k)
                        + ": "
                        + ("None" if self.callees[k] is None else self.callees[k].name),
                        self.callees,
                    )
                )
                + "}"
            )
        if self.pattern:
            result += ":" + str(self.pattern) + "@" + str(self.pattern_offset)
        result += ">"
        return result


TrieValueType = Any


class TrieNode(object):
    """
    A prefix tree, aka a Trie.
    This trie has several special characteristics:
     - The bytestrings of stem nodes can contain wildcards, which match any byte.
     - Bytestrings can start with a wildcard.
     - Nodes contain an array of function nodes, which represent functions matched by the pattern corresponding to that trie position.
     - Most importantly, the function nodes are themselves connected by a call graph (a directed graph).
    This means that all of the function nodes are actually interconnected orthogonally from the trie itself.
    In fact, a trie node may contain a function node that has a call edge to a function node which itself is not contained within the trie!
    In such cases, we refer to such nodes as "bridge" nodes, as they have no purpose for function matching other than
    to link two related functions via the call graph.

    Here is an example to illustrate:
    01
      2345: func1 (calls func2)
      4567: func3
    02
      5678: func4 (calls func3)
    func2 (not in any trie leaf node) calls func4

    In this case, there are six trie nodes (including the root), four function nodes, and `func2` is a bridge node.
    """

    def __init__(
        self,
        pattern: Pattern,
        children: Dict[MaskedByte, "TrieNode"],
        value: TrieValueType,
    ):
        """
        Don't call me directly. Call new_trie() instead to construct an empty trie and use insert() to add to it.

        :param pattern: Pattern object
        :param children: forms a trie of TrieNode. dict of {MaskedByte: child node}.
        :param value: array of FunctionNode present at this TrieNode
        """
        assert isinstance(pattern, Pattern)
        for elem in pattern:
            assert isinstance(elem, MaskedByte)

        self.pattern = pattern
        self.children = children
        self.value = value

    def __repr__(self) -> str:
        result = str(self.pattern)
        if self.value is not None:
            result += ":" + str(self.value)
        return result

    def find(self, buf: Pattern) -> List[TrieValueType]:
        """
        Traverses this prefix trie to find matched function nodes in a specified buffer of data.
        At each trie node visited, all function nodes contained by that node are appended to the results list.
        :param buf: bytes-like object
        :return: a list of `FunctionNode`s which match the given bytes
        """
        if not self.pattern.matches(buf):
            # print('no match', self)
            return []  # no match

        matches: List[TrieValueType] = []
        if self.value is not None:
            matches.extend(self.value)

        if len(self.pattern) == len(buf):
            # print('return matches1', len(self.pattern), len(buf))
            return matches
        buf = buf.slice(slice(len(self.pattern), None))

        next_byte = MaskedByte.new(buf[0].value, 1)
        # print('next_byte', next_byte)
        if next_byte in self.children:
            # print('trying children1', self.children[next_byte])
            matches.extend(self.children[next_byte].find(buf))

        wildcard = MaskedByte.wildcard()
        if wildcard in self.children:
            # print('trying children2', self.children[wildcard])
            matches.extend(self.children[wildcard].find(buf))

        # print('return matches2', matches)
        return matches

    def _is_degenerate(self) -> bool:
        """
        A trie node is degenerate it would match any byte sequence
        :return: if the pattern is empty or all wildcards
        """
        if not self.pattern:
            return True
        for m in self.pattern:
            if m.mask:
                return False
        return True

    def _split(self, j: int) -> None:
        split_node = TrieNode(
            self.pattern.slice(slice(j, None)), self.children, self.value
        )
        self.pattern = self.pattern.slice(slice(j))
        self.value = None
        if split_node._is_degenerate() and not split_node.children:
            # print('deleting degenerate node ', repr(split_node))
            for f in split_node.value:
                f.ref_count -= 1
            self.children = {}
            return
        self.children = {split_node.pattern[0]: split_node}

    def _add_child(self, child: "TrieNode") -> None:
        assert child.pattern[0] not in self.children
        assert isinstance(child.pattern[0], MaskedByte)
        self.children[child.pattern[0]] = child

    def insert(self, pattern: Pattern, value: TrieValueType) -> bool:
        """
        Inserts a new FunctionNode into this trie at the position specified by the pattern (`data`,`mask`).
        To avoid false postitives, the function node may be rejected from the trie and not inserted if the specified
        pattern is too short or too ambiguous.

        :param pattern: Pattern object
        :param value: `FunctionNode`
        :return: True if the function node was inserted, or False if it was rejected
        """
        if len(pattern) < 8:
            sys.stderr.write(
                f"Too short pattern for {value}: got {len(pattern)} want {MIN_PATTERN_LENGTH}\n"
            )
            return False
        if sum(map(lambda e: e.mask, pattern)) < 8:
            sys.stderr.write(f"Too ambiguous mask for {value}\n")
            return False

        i = 0
        j = 0
        node = self
        while i < len(pattern):
            if j == len(node.pattern):  # end of node
                j = 0
                if pattern[i] in node.children:  # next node
                    node = node.children[pattern[i]]
                else:  # we need to insert a new node
                    new_node = TrieNode(pattern.slice(slice(i, None)), {}, None)
                    node._add_child(new_node)
                    node = new_node
                    break
            elif pattern[i] != node.pattern[j]:  # need to split node
                node._split(j)
                new_node = TrieNode(pattern.slice(slice(i, None)), {}, None)
                node._add_child(new_node)
                node = new_node
                break
            else:
                i += 1
                j += 1

        if node.value is None:
            node.value = [value]
        else:
            node.value.append(value)
            # sys.stderr.write('Ambiguous functions %s\n' % (node,))
        value.ref_count += 1
        return True

    def pretty_print(self, prefix_len: int = 0) -> str:
        indent = "  " * prefix_len
        result = indent + repr(self)
        for child in self.children.values():
            result += "\n" + child.pretty_print(prefix_len + len(self.pattern))
        return result

    def all_nodes(self) -> Generator["TrieNode", None, None]:
        """
        Yields all the trie nodes in this subtree using a simple DFS.
        :return: generator of `TrieNode`
        """
        yield self
        for k, child in sorted(self.children.items()):
            for node in child.all_nodes():
                yield node

    def all_values(self) -> Generator[TrieValueType, None, None]:
        """
        Yields function nodes that are directly contained by some trie node within this subtrie.
        Doesn't include "bridge" nodes!
        :return: generator of `FunctionNode`
        """
        for node in self.all_nodes():
            if node.value:
                for val in node.value:
                    yield val

    def all_functions(self) -> Generator[FunctionNode, None, None]:
        """
        Yields ALL function nodes, including bridge nodes by performing a DFS on the callgraph as well.
        Note that if this is called on a subtree, these functions may not be in under this subtree!
        Therefore, it only really makes sense to call this on the root node.
        :return: generator of `FunctionNode`
        """

        def visit(func_node, visited):  # callgraph dfs
            if func_node is None or func_node in visited:
                return
            visited.add(func_node)
            yield func_node
            for callee in func_node.callees.values():
                for func in visit(callee, visited):
                    yield func

        visited: Set[FunctionNode] = set()
        for func_node in self.all_values():
            for func in visit(func_node, visited):
                yield func


def new_trie() -> TrieNode:
    """
    Constructs a new, empty signature trie.
    :return: an empty trie
    """
    return TrieNode(Pattern(b"", []), {}, None)
