from packages.crypto.providers.software import SoftwareSigner
from packages.crypto.verification import verify_signature


def test_valid_signature_verifies():
    signer = SoftwareSigner.generate()

    data = b"AEGIS official communication"

    signature = signer.sign(data)

    assert verify_signature(
        data=data,
        signature=signature,
        public_key=signer.public_key(),
    )


def test_modified_data_fails_verification():
    signer = SoftwareSigner.generate()

    original_data = b"AEGIS official communication"
    modified_data = b"AEGIS fake communication"

    signature = signer.sign(original_data)

    assert not verify_signature(
        data=modified_data,
        signature=signature,
        public_key=signer.public_key(),
    )


def test_wrong_signature_fails_verification():
    signer = SoftwareSigner.generate()

    data = b"AEGIS official communication"

    signature = signer.sign(data)

    tampered_signature = bytearray(signature)
    tampered_signature[0] ^= 0x01

    assert not verify_signature(
        data=data,
        signature=bytes(tampered_signature),
        public_key=signer.public_key(),
    )