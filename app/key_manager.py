import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEY_FOLDER = "keys"

def generate_user_keys(username):
    os.makedirs(KEY_FOLDER, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_key_path = os.path.join(KEY_FOLDER, f"{username}_private.pem")
    public_key_path = os.path.join(KEY_FOLDER, f"{username}_public.pem")

    with open(private_key_path, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(public_key_path, "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return private_key_path, public_key_path