import os
import sys

binjaroot_path = os.path.expanduser('~/Applications/Binary Ninja.app/Contents/Resources/python/')
if binjaroot_path not in sys.path:
    sys.path.append(binjaroot_path)

try:
    from binaryninja import SymbolType
except ImportError:
    from enum import Enum
    class SymbolType(Enum):  # type: ignore
        FunctionSymbol = 0
        Other = 1
