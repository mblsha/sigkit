try:
    from binaryninja import SymbolType
except ImportError:
    from enum import Enum
    class SymbolType(Enum):  # type: ignore
        FunctionSymbol = 0
        Other = 1

