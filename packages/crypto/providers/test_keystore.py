import pytest

from packages.crypto.providers.keystore import (
    InvalidPasswordError,
    decrypt_private_key,
    encrypt_private_key,
)


def test_encrypt_decrypt_round_trip():
    private_key = b"AEGIS-DEVELOPMENT-PRIVATE-KEY"
    password = "correct horse battery staple"

    salt, nonce, ciphertext = encrypt_private_key(
        private_key,
        password,
    )

    recovered = decrypt_private_key(
        ciphertext,
        password,
        salt,
        nonce,
    )

    assert recovered == private_key
    assert ciphertext != private_key


def test_wrong_password_fails():
    private_key = b"AEGIS-DEVELOPMENT-PRIVATE-KEY"

    salt, nonce, ciphertext = encrypt_private_key(
        private_key,
        "correct-password",
    )

    with pytest.raises(InvalidPasswordError):
        decrypt_private_key(
            ciphertext,
            "wrong-password",
            salt,
            nonce,
        )


def test_tampered_ciphertext_fails():
    private_key = b"AEGIS-DEVELOPMENT-PRIVATE-KEY"

    salt, nonce, ciphertext = encrypt_private_key(
        private_key,
        "correct-password",
    )

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01

    with pytest.raises(InvalidPasswordError):
        decrypt_private_key(
            bytes(tampered),
            "correct-password",
            salt,
            nonce,
        )


def test_tampered_associated_data_fails():
    private_key = b"AEGIS-DEVELOPMENT-PRIVATE-KEY"

    salt, nonce, ciphertext = encrypt_private_key(
        private_key,
        "correct-password",
    )

    with pytest.raises(InvalidPasswordError):
        decrypt_private_key(
            ciphertext,
            "correct-password",
            salt,
            nonce,
            associated_data=b"ATTACKER-CONTROLLED-VALUE",
        )