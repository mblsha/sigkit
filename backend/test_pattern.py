from .signaturelibrary import Pattern, MaskedByte


def test_pattern_new():
    p = Pattern(b"\x12\x34", [0, 1])
    assert str(p) == "??34"


def test_pattern_from_str():
    p = Pattern.from_str("??34")
    assert str(p) == "??34"
    assert len(p) == 2
    assert p[0] == MaskedByte.wildcard()
    assert p[1] == MaskedByte.new(0x34, 1)

    p = Pattern.from_str("1234")
    assert str(p) == "1234"
    assert len(p) == 2
    assert p[0] == MaskedByte.new(0x12, 1)
    assert p[1] == MaskedByte.new(0x34, 1)


def test_pattern_matches():
    p = Pattern.from_str("??34")
    assert p.matches(b"\x12\x34")

    p = Pattern.from_str("1234")
    assert p.matches(b"\x12\x34")

    p = Pattern.from_str("??34")
    assert not p.matches(b"\x12\x35")

    p = Pattern.from_str("1234")
    assert not p.matches(b"\x12\x35")


def test_pattern_intersect():
    a = Pattern.from_str("??34")
    b = Pattern.from_str("??34")
    assert str(a.intersect(b)) == "??34"

    a = Pattern.from_str("??34")
    b = Pattern.from_str("??35")
    assert not a.intersect(b)

    a = Pattern.from_str("??34")
    b = Pattern.from_str("12??")
    assert str(a.intersect(b)) == "1234"


def test_pattern_union():
    a = Pattern.from_str("??34")
    b = Pattern.from_str("??34")
    assert str(a.union(b)) == "??34"

    a = Pattern.from_str("??34")
    b = Pattern.from_str("??35")
    assert str(a.union(b)) == "????"

    a = Pattern.from_str("??34")
    b = Pattern.from_str("12??")
    assert str(a.union(b)) == "????"

    a = Pattern.from_str("??34")
    b = Pattern.from_str("1234")
    assert str(a.union(b)) == "??34"


def test_pattern_data():
    p = Pattern.from_str("??34")
    assert bytes(p.data()) == b"\x00\x34"

    p = Pattern.from_str("1234")
    assert bytes(p.data()) == b"\x12\x34"


def test_pattern_mask():
    p = Pattern.from_str("??34")
    assert list(p.mask()) == [0, 1]

    p = Pattern.from_str("1234")
    assert list(p.mask()) == [1, 1]