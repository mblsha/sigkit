from .compute_sig import simplify_filename

def test_simplify_filename() -> None:
    sf = simplify_filename
    assert sf("foo.obj") == "foo"
    assert sf("foo.obj.o") == "foo"
    assert sf("bar/blah") == "bar/blah"
    assert sf("foo/bar/blah") == "bar/blah"
    assert sf("foo/bar/blah.obj.o") == "bar/blah"
