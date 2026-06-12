import json
import os
from werkzeug.security import generate_password_hash, check_password_hash

USER_FILE = "data/users.json"


def load_users():
    if not os.path.exists(USER_FILE):
        return {}

    with open(USER_FILE, "r") as file:
        return json.load(file)


def save_users(users):
    os.makedirs("data", exist_ok=True)

    with open(USER_FILE, "w") as file:
        json.dump(users, file, indent=4)


def register_user(username, password, private_key_path, public_key_path, certificate_path):
    users = load_users()

    if username in users:
        return False

    users[username] = {
        "password_hash": generate_password_hash(password),
        "role": "user",
        "private_key": private_key_path,
        "public_key": public_key_path,
        "certificate": certificate_path,
        "certificate_status": "valid"
    }

    save_users(users)
    return True


def authenticate_user(username, password):
    users = load_users()

    if username not in users:
        return False

    stored_hash = users[username]["password_hash"]

    return check_password_hash(stored_hash, password)


def get_user(username):
    users = load_users()
    return users.get(username)