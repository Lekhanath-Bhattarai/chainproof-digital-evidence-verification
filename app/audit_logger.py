import json
import os
from datetime import datetime

LOG_FILE = "data/audit_logs.json"


def load_logs():
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r") as file:
        return json.load(file)


def save_logs(logs):
    os.makedirs("data", exist_ok=True)

    with open(LOG_FILE, "w") as file:
        json.dump(logs, file, indent=4)


def add_log(username, action, details):
    logs = load_logs()

    logs.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "action": action,
        "details": details
    })

    save_logs(logs)