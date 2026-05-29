"""Derived Fernet instance is cached (perf) without breaking round-trips."""
import time


def test_fernet_instance_is_cached():
    import config
    assert config.fernet() is config.fernet()


def test_cached_fernet_still_roundtrips():
    import config
    token = config.encrypt("secret-value")
    assert config.decrypt(token) == "secret-value"
    assert config.decrypt(token[:-2] + "AA") is None  # tamper still rejected


def test_repeated_encrypt_is_cheap():
    # 200 encrypts must not each pay a 200k-iteration PBKDF2 (would be seconds).
    import config
    config.fernet()  # warm the cache
    t0 = time.perf_counter()
    for i in range(200):
        config.decrypt(config.encrypt(f"v{i}"))
    assert time.perf_counter() - t0 < 1.0
