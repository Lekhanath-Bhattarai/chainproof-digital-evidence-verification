import json
import os
from datetime import datetime

EVIDENCE_FILE = "data/evidence_records.json"


def load_records():
    if not os.path.exists(EVIDENCE_FILE):
        return []

    with open(EVIDENCE_FILE, "r") as file:
        return json.load(file)


def save_records(records):
    with open(EVIDENCE_FILE, "w") as file:
        json.dump(records, file, indent=4)


def add_record(username, filename, file_hash, signature_path):
    records = load_records()

    records.append({
        "username": username,
        "filename": filename,
        "hash": file_hash,
        "signature": signature_path,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    save_records(records)