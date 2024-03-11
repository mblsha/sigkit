from .binja_api import SymbolType
from .signaturelibrary import (
    MaskedByte,
    Pattern,
    FunctionInfo,
    FunctionNode,
    str_to_bytes,
)

from typing import Dict, Tuple


def b(s: str) -> MaskedByte:
    return MaskedByte.from_str(s)


bb = str_to_bytes


def p(s: str) -> Pattern:
    return Pattern.from_str(s)


def node(
    s: str,
    ref_count: int = 0,
    source_binary: str = "",
    pattern: Pattern = Pattern.empty_pattern(),
    pattern_offset: int = 0,
) -> FunctionNode:
    r = FunctionNode(s)
    r.ref_count = ref_count
    r.source_binary = source_binary
    r.pattern = pattern
    r.pattern_offset = pattern_offset
    return r


def info(s: str, callees: Dict[int, Tuple[str, SymbolType]] = {}) -> FunctionInfo:
    r = FunctionInfo([Pattern.from_str(s)])
    r.callees = callees
    return r
