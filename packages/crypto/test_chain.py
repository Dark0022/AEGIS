from cryptography import x509
from cryptography.x509.oid import NameOID

from packages.crypto.chain import (
    ChainValidationError,
    validate_institution_chain,
    validate_issuer_chain,
)
from packages.crypto.pki import (
    build_institution_ca_certificate,
    build_issuer_certificate,
    build_root_certificate,
    generate_ed25519_keypair,
)


def create_test_chain():
    root_key = generate_ed25519_keypair()

    root_cert = build_root_certificate(
        root_key,
        common_name="AEGIS Test Root CA",
        organization="AEGIS Test",
    )

    institution_key = generate_ed25519_keypair()

    institution_cert = build_institution_ca_certificate(
        institution_key,
        root_key,
        root_cert,
        common_name="SOA University CA",
        organization="SOA University",
    )

    issuer_key = generate_ed25519_keypair()

    issuer_cert = build_issuer_certificate(
        issuer_key,
        institution_key,
        institution_cert,
        common_name="Emergency Communications",
        organization="SOA University",
        organizational_unit="Emergency Management Office",
    )

    return (
        root_key,
        root_cert,
        institution_key,
        institution_cert,
        issuer_key,
        issuer_cert,
    )


def test_valid_institution_chain():
    _, root_cert, _, institution_cert, _, _ = create_test_chain()

    validate_institution_chain(
        institution_cert,
        root_cert,
    )


def test_wrong_root_is_rejected():
    _, _, _, institution_cert, _, _ = create_test_chain()

    wrong_root_key = generate_ed25519_keypair()

    wrong_root_cert = build_root_certificate(
        wrong_root_key,
        common_name="Wrong Root CA",
        organization="Untrusted",
    )

    try:
        validate_institution_chain(
            institution_cert,
            wrong_root_cert,
        )
    except ChainValidationError:
        return

    raise AssertionError(
        "A certificate signed by another root was accepted."
    )


def test_non_ca_institution_certificate_is_rejected():
    root_key, root_cert, institution_key, _, _, _ = create_test_chain()

    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "SOA University",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "Not A CA",
            ),
        ]
    )

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(institution_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(root_cert.not_valid_before_utc)
        .not_valid_after(root_cert.not_valid_after_utc)
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
            critical=True,
        )
        .sign(
            root_key,
            algorithm=None,
        )
    )

    try:
        validate_institution_chain(
            certificate,
            root_cert,
        )
    except ChainValidationError:
        return

    raise AssertionError(
        "A non-CA certificate was accepted as an Institution CA."
    )


def test_valid_three_level_issuer_chain():
    (
        _,
        root_cert,
        _,
        institution_cert,
        _,
        issuer_cert,
    ) = create_test_chain()

    validate_issuer_chain(
        issuer_cert,
        institution_cert,
        root_cert,
    )


def test_issuer_is_not_allowed_to_be_a_ca():
    (
        root_key,
        root_cert,
        institution_key,
        institution_cert,
        issuer_key,
        _,
    ) = create_test_chain()

    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "SOA University",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "Invalid Issuer CA",
            ),
        ]
    )

    invalid_issuer = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(institution_cert.subject)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            institution_cert.not_valid_before_utc
        )
        .not_valid_after(
            institution_cert.not_valid_after_utc
        )
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=0,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(
            institution_key,
            algorithm=None,
        )
    )

    try:
        validate_issuer_chain(
            invalid_issuer,
            institution_cert,
            root_cert,
        )
    except ChainValidationError:
        return

    raise AssertionError(
        "An Authorized Issuer certificate with CA=true was accepted."
    )


def test_issuer_without_digital_signature_usage_is_rejected():
    (
        root_key,
        root_cert,
        institution_key,
        institution_cert,
        issuer_key,
        _,
    ) = create_test_chain()

    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "SOA University",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "Invalid Signature Issuer",
            ),
        ]
    )

    invalid_issuer = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(institution_cert.subject)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            institution_cert.not_valid_before_utc
        )
        .not_valid_after(
            institution_cert.not_valid_after_utc
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(
            institution_key,
            algorithm=None,
        )
    )

    try:
        validate_issuer_chain(
            invalid_issuer,
            institution_cert,
            root_cert,
        )
    except ChainValidationError:
        return

    raise AssertionError(
        "An issuer without digitalSignature usage was accepted."
    )


def test_issuer_cannot_sign_crls():
    (
        root_key,
        root_cert,
        institution_key,
        institution_cert,
        issuer_key,
        _,
    ) = create_test_chain()

    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "SOA University",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "CRL Issuer",
            ),
        ]
    )

    invalid_issuer = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(institution_cert.subject)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            institution_cert.not_valid_before_utc
        )
        .not_valid_after(
            institution_cert.not_valid_after_utc
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(
            institution_key,
            algorithm=None,
        )
    )

    try:
        validate_issuer_chain(
            invalid_issuer,
            institution_cert,
            root_cert,
        )
    except ChainValidationError:
        return

    raise AssertionError(
        "An Authorized Issuer allowed to sign CRLs was accepted."
    )