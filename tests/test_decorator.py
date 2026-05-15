"""
Tests for policy/decorator.py (currently an empty stub) and exceptions.py.
"""
import pytest
from exceptions import SecurityException, Unauthorized, Forbidden


# ---------------------------------------------------------------------------
# policy/decorator.py — empty module, import check
# ---------------------------------------------------------------------------

def test_decorator_module_importable():
    import policy.decorator as dec_mod
    assert dec_mod is not None


# ---------------------------------------------------------------------------
# exceptions.py
# ---------------------------------------------------------------------------

def test_security_exception_is_exception():
    err = SecurityException("base")
    assert isinstance(err, Exception)
    assert str(err) == "base"


def test_unauthorized_inherits_security_exception():
    err = Unauthorized("no token")
    assert isinstance(err, SecurityException)
    assert isinstance(err, Exception)
    assert str(err) == "no token"


def test_forbidden_inherits_security_exception():
    err = Forbidden("access denied")
    assert isinstance(err, SecurityException)
    assert isinstance(err, Exception)
    assert str(err) == "access denied"


def test_raise_and_catch_unauthorized():
    with pytest.raises(Unauthorized) as exc_info:
        raise Unauthorized("missing bearer token")
    assert "missing bearer token" in str(exc_info.value)


def test_raise_and_catch_forbidden():
    with pytest.raises(Forbidden) as exc_info:
        raise Forbidden("insufficient permissions")
    assert "insufficient permissions" in str(exc_info.value)


def test_catch_unauthorized_as_security_exception():
    with pytest.raises(SecurityException):
        raise Unauthorized("bad token")


def test_catch_forbidden_as_security_exception():
    with pytest.raises(SecurityException):
        raise Forbidden("not allowed")


def test_unauthorized_and_forbidden_are_distinct():
    # Neither should be a subclass of the other
    assert not issubclass(Unauthorized, Forbidden)
    assert not issubclass(Forbidden, Unauthorized)
