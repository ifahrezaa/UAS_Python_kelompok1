# Bagian 3 — Data & Enkripsi
from pwkeeper_utils import *
from cryptography.fernet import Fernet

# ---------- Data ----------
def load_accounts():
    return load_json(DATA_FILE, [])

def save_accounts(accounts):
    save_json(DATA_FILE, accounts)

def encrypt_password(fernet: Fernet, plaintext: str) -> str:
    token = fernet.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")

def decrypt_password(fernet: Fernet, token: str) -> str:
    return fernet.decrypt(token.encode("utf-8")).decode("utf-8")