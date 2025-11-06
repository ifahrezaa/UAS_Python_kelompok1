import json
from crypto_utils import encrypt_data, decrypt_data

def load_data(file_path, key):
    """Membaca dan mendekripsi data dari file"""
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        for k, v in data.items():
            data[k] = decrypt_data(v.encode(), key)
        return data
    except:
        return {}

def save_data(file_path, data, key):
    """Mengenkripsi dan menyimpan data ke file"""
    encrypted_data = {k: encrypt_data(v, key).decode() for k, v in data.items()}
    with open(file_path, "w") as f:
        json.dump(encrypted_data, f, indent=4)