import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

SIGNATURE_FOLDER = "signatures"

def sign_file(file_path, private_key_path):
    os.makedirs(SIGNATURE_FOLDER, exist_ok=True)

    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    with open(file_path, "rb") as file:
        file_data = file.read()

    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    filename = os.path.basename(file_path)
    signature_path = os.path.join(SIGNATURE_FOLDER, f"{filename}.sig")

    with open(signature_path, "wb") as sig_file:
        sig_file.write(signature)

    return signature_path