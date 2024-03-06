from .signaturelibrary import (
    MaskedByte,
    Pattern,
    FunctionInfo,
    FunctionNode,
    str_to_bytes,
)

def b(s: str) -> MaskedByte:
    return MaskedByte.from_str(s)


bb = str_to_bytes


def p(s: str) -> Pattern:
    return Pattern.from_str(s)


def node(s: str, ref_count: int = 0) -> FunctionNode:
    r = FunctionNode(s)
    r.ref_count = ref_count
    return r


def info(s: str) -> FunctionInfo:
    return FunctionInfo([Pattern.from_str(s)])
