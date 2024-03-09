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
This file contains a signature matcher implementation in Python. This
implementation is only an illustrative example and should be used for testing
purposes only. It is extremely slow compared to the native implementation
found in Binary Ninja. Furthermore, the algorithm shown here is outdated
compared to the native implementation, so matcher results will be of inferior
quality.
"""

import sys

from binaryninja import BinaryView, Function, MediumLevelILOperation

from ..backend.signaturelibrary import TrieNode, FunctionNode
from ..sigkit import compute_sig

from typing import List, Dict, Optional, Tuple

from enum import Enum


class MatchResult(Enum):
    NO_MATCH = 0
    DISAMBIGUATION_MISMATCH = 1
    CALL_SITES_MISMATCH = 2
    CALLEE_MISMATCH = 3
    FULL_MATCH = 999


class MatchError(Enum):
    THUNK_RECURSION_LIMIT = 1
    THUNK_JUMP_SRC = 2
    THUNK_DEST_NOT_FOUND = 3

    MATCH_FUNC_IS_NONE = 4
    MATCH_FUNC_NODE_IS_NONE = 5
    MATCH_ALREADY_VISITED = 6
    MATCH_ALREADY_MATCHED = 7
    MATCH_INVERSE_ALREADY_MATCHED = 8
    MATCH_TRIE_MISMATCH = 9
    MATCH_DISAMBIGUATION_MISMATCH = 10
    MATCH_CALL_SITE_NOT_IN_FUNC_NODE_CALLEES = 11
    MATCH_CALL_SITE_NOT_IN_FUNC_CALLEES = 12
    MATCH_CALLEE_MISMATCH = 13
    MATCH_CONFLICT = 14
    MATCH_INVERSE_CONFLICT = 15


class SignatureMatcher(object):
    def __init__(self, sig_trie: TrieNode, bv: BinaryView):
        self.sig_trie = sig_trie
        self.bv = bv

        self._matches: Dict[Function, FunctionNode] = {}
        self._matches_inv: Dict[FunctionNode, Function] = {}
        self.results: Dict[Function, FunctionNode] = {}

        self._cur_match_debug = ""

    def resolve_thunk(
        self, func: Function, level: int = 0
    ) -> Tuple[Function, Optional[MatchError]]:
        if compute_sig.get_func_len(func) >= 8:
            return func, None

        first_insn = func.mlil[0]
        if first_insn.operation == MediumLevelILOperation.MLIL_TAILCALL:
            thunk_dest = self.bv.get_function_at(first_insn.dest.value.value)
        elif (
            first_insn.operation == MediumLevelILOperation.MLIL_JUMP
            and first_insn.dest.operation == MediumLevelILOperation.MLIL_LOAD
            and first_insn.dest.src.operation == MediumLevelILOperation.MLIL_CONST_PTR
        ):
            data_var = self.bv.get_data_var_at(first_insn.dest.src.value.value)
            if not data_var or not data_var.data_refs_from:
                return None, MatchError.THUNK_JUMP_SRC
            thunk_dest = self.bv.get_function_at(data_var.data_refs_from[0])
        else:
            return func, None

        if thunk_dest is None:
            return None, MatchError.THUNK_DEST_NOT_FOUND

        if level >= 100:
            # something is wrong here. there's a weird infinite loop of thunks.
            return None, MatchError.THUNK_RECURSION_LIMIT

        return self.resolve_thunk(thunk_dest, level + 1)

    def on_match(self, func: Function, func_node: FunctionNode) -> Optional[MatchError]:
        result: Optional[MatchError] = None
        if func in self._matches:
            result = MatchError.MATCH_ALREADY_MATCHED
            if self._matches[func] != func_node:
                result = MatchError.MATCH_CONFLICT
                if func in self.results:
                    del self.results[func]
            return result

        self.results[func] = func_node

        if func_node in self._matches_inv:
            result = MatchError.MATCH_INVERSE_ALREADY_MATCHED
            if self._matches_inv[func_node] != func:
                result = MatchError.MATCH_INVERSE_CONFLICT
            return result

        self._matches[func] = func_node
        self._matches_inv[func_node] = func
        return result

    def compute_func_callees(self, func: Function) -> Dict[int, Function]:
        """
        Return a list of the names of symbols the function calls.
        """
        callees: Dict[int, Function] = {}
        for ref in func.call_sites:
            callee_addrs = self.bv.get_callees(ref.address, ref.function, ref.arch)
            if len(callee_addrs) != 1:
                continue
            callees[ref.address - func.start] = self.bv.get_function_at(callee_addrs[0])
        return callees

    def does_func_match(
        self,
        func: Function,
        func_node: FunctionNode,
        visited: Dict[Function, FunctionNode],
        level: int = 0,
    ) -> Tuple[MatchResult, Optional[MatchError]]:
        # we expect a function to be here but there isn't one. no match.
        if func is None:
            return MatchResult.NO_MATCH, MatchError.MATCH_FUNC_IS_NONE

        # no information about this function. assume wildcard.
        if func_node is None:
            return MatchResult.FULL_MATCH, MatchError.MATCH_FUNC_NODE_IS_NONE

        # fix for msvc thunks -.-
        thunk_dest, thunk_error = self.resolve_thunk(func)
        if not thunk_dest:
            return MatchResult.NO_MATCH, thunk_error
        func = thunk_dest

        # this is essentially a dfs on the callgraph. if we encounter a backedge,
        # treat it optimistically, implying that the callers match if the callees match.
        # however, we track our previous assumptions, meaning that if we previously
        # optimistically assumed b == a, then later on if we compare b and c, we say
        # that b != c since we already assumed b == a (and c != a)
        if func in visited:
            return (
                MatchResult.FULL_MATCH
                if visited[func] == func_node
                else MatchResult.NO_MATCH
            ), MatchError.MATCH_ALREADY_VISITED
        visited[func] = func_node

        # if we've already figured out what this function is, don't waste our time doing it again.
        if func in self._matches:
            return (
                MatchResult.FULL_MATCH
                if self._matches[func] == func_node
                else MatchResult.NO_MATCH
            ), MatchError.MATCH_ALREADY_MATCHED

        func_len = compute_sig.get_func_len(func)
        func_data = self.bv.read(func.start, func_len)
        if not func_node.is_bridge:
            trie_matches = self.sig_trie.find(func_data)
            if func_node not in trie_matches:
                return MatchResult.NO_MATCH, MatchError.MATCH_TRIE_MISMATCH

        disambiguation_data = func_data[
            func_node.pattern_offset : func_node.pattern_offset + len(func_node.pattern)
        ]
        if not func_node.pattern.matches(disambiguation_data):
            return (
                MatchResult.DISAMBIGUATION_MISMATCH,
                MatchError.MATCH_DISAMBIGUATION_MISMATCH,
            )

        callees = self.compute_func_callees(func)
        for call_site in callees:
            if call_site not in func_node.callees:
                return (
                    MatchResult.CALL_SITES_MISMATCH,
                    MatchError.MATCH_CALL_SITE_NOT_IN_FUNC_NODE_CALLEES,
                )
        for call_site, callee in func_node.callees.items():
            if callee is not None and call_site not in callees:
                return (
                    MatchResult.CALL_SITES_MISMATCH,
                    MatchError.MATCH_CALL_SITE_NOT_IN_FUNC_CALLEES,
                )

        for call_site in callees:
            if (
                self.does_func_match(
                    callees[call_site], func_node.callees[call_site], visited, level + 1
                )[0]
                != MatchResult.FULL_MATCH
            ):
                return MatchResult.CALLEE_MISMATCH, MatchError.MATCH_CALLEE_MISMATCH

        self.on_match(func, func_node)
        return MatchResult.FULL_MATCH, None

    def process_func(self, func: Function) -> List[Function]:
        """
        Try to sig the given function.
        Return the list of signatures the function matched against
        """
        func_len = compute_sig.get_func_len(func)
        func_data = self.bv.read(func.start, func_len)
        trie_matches = self.sig_trie.find(func_data)

        best_score, results = MatchResult.NO_MATCH, []
        for candidate_func in trie_matches:
            score, error = self.does_func_match(func, candidate_func, {})
            if score.value > best_score.value:
                results = [candidate_func]
                best_score = score
            elif score == best_score:
                results.append(candidate_func)

        if len(results) == 0:
            assert best_score == MatchResult.NO_MATCH
            return results
        elif len(results) > 1:
            print(func.name, "=>", "deferred at level", best_score, results)
            return results

        match = results[0]
        self._cur_match_debug = str(best_score)
        self.on_match(func, match)
        return results

    def run_pass(self, queue: List[Function]) -> List[Function]:
        deferred = []
        print("Start of pass %d functions remaining" % (len(queue)))

        for func in queue:
            if func in self._matches:
                continue
            if compute_sig.get_func_len(func) < 8:
                continue
            matches = self.process_func(func)
            if len(matches) > 1:
                deferred.append(func)

        print("Pass complete, %d functions deferred" % (len(deferred),))
        if len(queue) == len(deferred):
            print("No changes. Quit.")
            return []
        return deferred

    def run(self) -> None:
        queue = self.bv.functions
        while True:  # silly fixedpoint worklist algorithm
            deferred = self.run_pass(queue)
            if not deferred:
                break
            queue = deferred
