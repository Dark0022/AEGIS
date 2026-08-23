from cryptography import x509

from packages.crypto.pki import (
    C2PA_CLAIM_SIGNING_EKU,
    DOCUMENT_SIGNING_EKU,
    ROOT_PATH_LENGTH,
    build_issuer_certificate,
    build_institution_ca_certificate,
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


def test_root_certificate_is_self_signed():
    private_key = generate_ed25519_keypair()

    certificate = build_root_certificate(private_key)

    assert certificate.subject == certificate.issuer
    assert (
        certificate.public_key().public_bytes_raw()
        == private_key.public_key().public_bytes_raw()
    )


def test_root_certificate_has_correct_ca_constraints():
    private_key = generate_ed25519_keypair()

    certificate = build_root_certificate(private_key)

    basic_constraints = certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value

    assert basic_constraints.ca is True
    assert basic_constraints.path_length == ROOT_PATH_LENGTH


def test_root_certificate_has_correct_key_usage():
    private_key = generate_ed25519_keypair()

    certificate = build_root_certificate(private_key)

    key_usage = certificate.extensions.get_extension_for_class(
        x509.KeyUsage
    ).value

    assert key_usage.key_cert_sign is True
    assert key_usage.crl_sign is True
    assert key_usage.digital_signature is False


def test_root_certificate_is_valid_now():
    private_key = generate_ed25519_keypair()

    certificate = build_root_certificate(
        private_key,
        validity_days=10,
    )

    assert (
        certificate.not_valid_before_utc
        <= certificate.not_valid_after_utc
    )


def test_issuer_has_c2pa_claim_signing_eku():
    (
        _,
        _,
        _,
        _,
        _,
        issuer_certificate,
    ) = create_test_chain()

    eku = issuer_certificate.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value

    assert C2PA_CLAIM_SIGNING_EKU in eku


def test_issuer_has_document_signing_eku():
    (
        _,
        _,
        _,
        _,
        _,
        issuer_certificate,
    ) = create_test_chain()

    eku = issuer_certificate.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value

    assert DOCUMENT_SIGNING_EKU in eku


def test_issuer_is_not_a_ca():
    (
        _,
        _,
        _,
        _,
        _,
        issuer_certificate,
    ) = create_test_chain()

    basic_constraints = issuer_certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value

    assert basic_constraints.ca is False


def test_issuer_allows_digital_signatures():
    (
        _,
        _,
        _,
        _,
        _,
        issuer_certificate,
    ) = create_test_chain()

    key_usage = issuer_certificate.extensions.get_extension_for_class(
        x509.KeyUsage
    ).value

    assert key_usage.digital_signature is True
    assert key_usage.key_cert_sign is False
    assert key_usage.crl_sign is False