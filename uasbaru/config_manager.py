import os

DATA_FILE = "vault_data.json"
CONFIG_FILE = "config.json"

def ensure_files_exist():
    """Pastikan file data ada, jika tidak buat kosong"""
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as f:
            f.write("{}")