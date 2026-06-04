"""Smoke tests for crypto (Fernet) and auth (PBKDF2)."""


def test_fernet_roundtrip():
    import config
    encrypted = config.encrypt("hello world")
    assert config.decrypt(encrypted) == "hello world"


def test_fernet_tampered_returns_none():
    import config
    encrypted = config.encrypt("hello")
    # Mutate one character of the cipher
    tampered = encrypted[:-2] + "AA"
    assert config.decrypt(tampered) is None


def test_password_hash_verify():
    import auth
    h = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("correct horse battery staple", h)
    assert not auth.verify_password("wrong password", h)


def test_password_hash_different_each_time():
    """Different salts produce different hashes for the same password."""
    import auth
    h1 = auth.hash_password("samepass")
    h2 = auth.hash_password("samepass")
    assert h1 != h2
    assert auth.verify_password("samepass", h1)
    assert auth.verify_password("samepass", h2)


def test_password_hash_format():
    """Hashes follow the documented pbkdf2$iters$salt_b64$hash_b64 format."""
    import auth
    h = auth.hash_password("any")
    parts = h.split("$")
    assert len(parts) == 4
    assert parts[0] == "pbkdf2"
    assert int(parts[1]) >= 100_000


def test_verify_malformed_returns_false():
    import auth
    assert not auth.verify_password("any", "not-a-hash")
    assert not auth.verify_password("any", "pbkdf2$bad$bad$bad")
    assert not auth.verify_password("any", "")
