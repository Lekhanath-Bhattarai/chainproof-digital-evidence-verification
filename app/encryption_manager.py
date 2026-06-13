import os
from cryptography.fernet import Fernet

STORAGE_KEY_PATH = "keys/storage_key.key"


def load_or_create_storage_key():
    os.makedirs("keys", exist_ok=True)

    if not os.path.exists(STORAGE_KEY_PATH):
        key = Fernet.generate_key()
        with open(STORAGE_KEY_PATH, "wb") as key_file:
            key_file.write(key)

    with open(STORAGE_KEY_PATH, "rb") as key_file:
        return key_file.read()


def encrypt_file(file_path):
    key = load_or_create_storage_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    encrypted_path = file_path + ".enc"

    with open(encrypted_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    return encrypted_path