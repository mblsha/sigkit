from .signaturelibrary import MaskedByte
import pytest


def test_maskedbyte_new():
    assert str(MaskedByte.new(0x12, 0)) == "??"
    assert str(MaskedByte.new(0x12, 1)) == "12"


def test_maskedbyte_from_str():
    assert str(MaskedByte.from_str("??")) == "??"
    assert str(MaskedByte.from_str("12")) == "12"

    with pytest.raises(AssertionError):
        MaskedByte.from_str("123")


def test_maskedbyte_le():
    a = MaskedByte.new(0x12, 1)
    b = MaskedByte.new(0x13, 1)
    assert a < b

    c = MaskedByte.new(0x12, 0)
    d = MaskedByte.new(0x13, 0)
    assert c == d


def test_maskedbyte_matches():
    a = MaskedByte.new(0x12, 1)
    b = MaskedByte.new(0x12, 1)
    assert a.matches(b)

    a = MaskedByte.new(0x12, 0)
    b = MaskedByte.new(0x12, 0)
    assert a.matches(b)

    a = MaskedByte.new(0x12, 1)
    b = MaskedByte.new(0x13, 1)
    assert not a.matches(b)

    a = MaskedByte.new(0x12, 0)
    b = MaskedByte.new(0xFF, 1)
    assert a.matches(b)

    # !!! this is an unexpected case
    a = MaskedByte.new(0x12, 1)
    b = MaskedByte.new(0xFF, 0)
    assert not a.matches(b)

    assert MaskedByte.new(0x12, 1).matches(0x12)
    assert not MaskedByte.new(0x12, 1).matches(0x13)

    assert MaskedByte.new(0x12, 0).matches(0x12)
    assert MaskedByte.new(0x12, 0).matches(0x13)

def test_maskedbyte_intersect():
    a = MaskedByte.new(0x12, 1)
    b = MaskedByte.new(0x12, 1)
    assert str(a.intersect(b)) == "12"

    a = MaskedByte.new(0x12, 1)
    b = MaskedByte.new(0x13, 1)
    assert not a.intersect(b)

    a = MaskedByte.new(0x12, 0)
    b = MaskedByte.new(0x12, 0)
    assert str(a.intersect(b)) == "??"

    a = MaskedByte.new(0x12, 0)
    b = MaskedByte.new(0xFF, 0)
    assert str(a.intersect(b)) == "??"

    a = MaskedByte.new(0x12, 1)
    b = MaskedByte.new(0xFF, 0)
    assert str(a.intersect(b)) == "12"

    a = MaskedByte.new(0x12, 0)
    b = MaskedByte.new(0xFF, 1)
    assert str(a.intersect(b)) == "ff"


def test_maskedbyte_union():
    a = MaskedByte.new(0x12, 0)
    b = MaskedByte.new(0xFF, 0)
    assert str(a.union(b)) == "??"

    a = MaskedByte.new(0x12, 1)
    b = MaskedByte.new(0xFF, 0)
    assert str(a.union(b)) == "??"

    a = MaskedByte.new(0x12, 0)
    b = MaskedByte.new(0xFF, 1)
    assert str(a.union(b)) == "??"

    a = MaskedByte.new(0x12, 1)
    b = MaskedByte.new(0xFF, 1)
    assert str(a.union(b)) == "??"

    a = MaskedByte.new(0x12, 1)
    b = MaskedByte.new(0x12, 1)
    assert str(a.union(b)) == "12"
