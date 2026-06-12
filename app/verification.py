from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def verify_signature(file_path, signature_path, certificate_path):
    with open(certificate_path, "rb") as cert_file:
        user_certificate = x509.load_pem_x509_certificate(cert_file.read())

    public_key = user_certificate.public_key()

    with open(file_path, "rb") as file:
        file_data = file.read()

    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()

    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def validate_certificate(certificate_path, ca_certificate_path, certificate_status):
    if certificate_status != "valid":
        return False, "Certificate has been revoked or disabled."

    with open(certificate_path, "rb") as cert_file:
        user_certificate = x509.load_pem_x509_certificate(cert_file.read())

    with open(ca_certificate_path, "rb") as ca_file:
        ca_certificate = x509.load_pem_x509_certificate(ca_file.read())

    now = datetime.now(timezone.utc)

    if now < user_certificate.not_valid_before_utc:
        return False, "Certificate is not yet valid."

    if now > user_certificate.not_valid_after_utc:
        return False, "Certificate has expired."

    ca_public_key = ca_certificate.public_key()

    try:
        ca_public_key.verify(
            user_certificate.signature,
            user_certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_certificate.signature_hash_algorithm
        )
    except InvalidSignature:
        return False, "Certificate was not issued by the trusted ChainProof CA."

    return True, "Certificate is valid."