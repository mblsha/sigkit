from .signaturelibrary import Pattern, MaskedByte, str_to_bytes


def test_pattern_new() -> None:
    p = Pattern(b"\x12\x34", [0, 1])
    assert str(p) == "??34"


def test_pattern_from_str() -> None:
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


def test_str_to_bytes() -> None:
    assert str_to_bytes("") == b""
    assert str_to_bytes("1234") == b"\x12\x34"
    assert str_to_bytes("123") == b"\x12\x03"


def test_pattern_to_bytes() -> None:
    b = str_to_bytes
    p = Pattern.from_str

    assert p("0034").to_bytes() == b("0034")
    assert p("??34").to_bytes() == b("0034")
    assert p("1234").to_bytes() == b("1234")


def test_pattern_matches() -> None:
    b = str_to_bytes
    p = Pattern.from_str

    # same length
    assert p("??34").matches(b("1234"))
    assert p("1234").matches(b("1234"))
    assert not p("??34").matches(b("1235"))
    assert not p("1234").matches(b("1235"))

    # greater length
    assert not p("123456").matches(b("1234"))

    # smaller length
    assert p("1234").matches(b("123456"))


def test_pattern_intersect() -> None:
    a = Pattern.from_str("??34")
    b = Pattern.from_str("??34")
    assert str(a.intersect(b)) == "??34"

    a = Pattern.from_str("??34")
    b = Pattern.from_str("??35")
    assert not a.intersect(b)

    a = Pattern.from_str("??34")
    b = Pattern.from_str("12??")
    assert str(a.intersect(b)) == "1234"


def test_pattern_union() -> None:
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


def test_pattern_data() -> None:
    p = Pattern.from_str("??34")
    assert bytes(p.data()) == b"\x00\x34"

    p = Pattern.from_str("1234")
    assert bytes(p.data()) == b"\x12\x34"


def test_pattern_mask() -> None:
    p = Pattern.from_str("??34")
    assert list(p.mask()) == [0, 1]

    p = Pattern.from_str("1234")
    assert list(p.mask()) == [1, 1]


def test_pattern_index() -> None:
    p = Pattern.from_str("??34")
    assert p[0] == MaskedByte.wildcard()
    assert p[1] == MaskedByte.new(0x34, 1)

    p = Pattern.from_str("1234")
    assert p[0] == MaskedByte.new(0x12, 1)
    assert p[1] == MaskedByte.new(0x34, 1)
