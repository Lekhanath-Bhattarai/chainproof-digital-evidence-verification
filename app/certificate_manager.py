import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERT_FOLDER = "certificates"
CA_KEY_PATH = os.path.join(CERT_FOLDER, "chainproof_ca_private.pem")
CA_CERT_PATH = os.path.join(CERT_FOLDER, "chainproof_ca.crt")


def create_root_ca():
    os.makedirs(CERT_FOLDER, exist_ok=True)

    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        return CA_KEY_PATH, CA_CERT_PATH

    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChainProof"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ChainProof Root CA"),
    ])

    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )

    with open(CA_KEY_PATH, "wb") as key_file:
        key_file.write(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(CA_CERT_PATH, "wb") as cert_file:
        cert_file.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

    return CA_KEY_PATH, CA_CERT_PATH


def issue_user_certificate(username, public_key_path):
    create_root_ca()

    with open(CA_KEY_PATH, "rb") as key_file:
        ca_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    with open(CA_CERT_PATH, "rb") as cert_file:
        ca_certificate = x509.load_pem_x509_certificate(cert_file.read())

    with open(public_key_path, "rb") as public_key_file:
        user_public_key = serialization.load_pem_public_key(public_key_file.read())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChainProof User"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    user_certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )

    certificate_path = os.path.join(CERT_FOLDER, f"{username}.crt")

    with open(certificate_path, "wb") as cert_file:
        cert_file.write(user_certificate.public_bytes(serialization.Encoding.PEM))

    return certificate_path