from hashlib import sha256

from packages.crypto.hashing import sha256_bytes


def test_sha256_bytes():
    data = b"AEGIS"

    expected = sha256(data).hexdigest()

    assert sha256_bytes(data) == expected