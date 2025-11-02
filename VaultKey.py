import os
import json
import base64
import uuid
import secrets
import hashlib
from pathlib import Path
from tkinter import (
    Tk, Toplevel, Frame, Label, Entry, Button, StringVar, END, messagebox, ttk
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ---------- File locations ----------
APP_DIR = Path.home() / ".pwkeeper"
APP_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = APP_DIR / "config.json"
DATA_FILE = APP_DIR / "passwords.json"
HINT_FILE = APP_DIR / "hint.json"

KDF_ITERATIONS = 390_000

# ---------- Utilities ----------
def save_json(path: Path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_json(path: Path, default):
    if not path.exists():
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------- Hint helpers ----------
def save_hint(hint_text: str):
    save_json(HINT_FILE, {"hint": hint_text or ""})

def load_hint() -> str:
    data = load_json(HINT_FILE, None)
    if not data:
        return ""
    return data.get("hint", "")

# ---------- Crypto ----------
def generate_salt(n=16):
    return secrets.token_bytes(n)

def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)

def hash_master_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, KDF_ITERATIONS).hex()

# ---------- Config ----------
def config_exists():
    return CONFIG_FILE.exists()

def create_config(master_password: str, hint_text: str = ""):
    salt = generate_salt()
    master_hash = hash_master_password(master_password, salt)
    cfg = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "master_hash": master_hash,
        "kdf_iterations": KDF_ITERATIONS
    }
    save_json(CONFIG_FILE, cfg)
    save_hint(hint_text)

def verify_master(master_password: str) -> bool:
    cfg = load_json(CONFIG_FILE, None)
    if not cfg:
        return False
    salt = base64.b64decode(cfg["salt"])
    candidate = hash_master_password(master_password, salt)
    return secrets.compare_digest(candidate, cfg["master_hash"])

def get_fernet_from_master(master_password: str) -> Fernet:
    cfg = load_json(CONFIG_FILE, None)
    if not cfg:
        raise ValueError("Config missing")
    salt = base64.b64decode(cfg["salt"])
    key = derive_key(master_password, salt)
    return Fernet(key)

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

# ---------- GUI ----------
class PasswordKeeperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VaultKey — Password Keeper")
        self.root.configure(bg="#e9f1f7")
        self.fernet = None
        self.accounts = []

        self.setup_style()
        self.setup_login_or_create()

    def setup_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TButton",
                        font=("Segoe UI", 10, "bold"),
                        foreground="white",
                        background="#0078D7",
                        padding=6)
        style.map("TButton", background=[("active", "#005A9E")])

        style.configure("Treeview",
                        font=("Segoe UI", 10),
                        rowheight=26,
                        fieldbackground="#fdfdfd",
                        background="#fdfdfd")
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def center_window(self, win, width, height):
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = (sw - width) // 2
        y = (sh - height) // 2
        win.geometry(f"{width}x{height}+{x}+{y}")

    def setup_login_or_create(self):
        if not config_exists():
            self.show_setup_master_window()
        else:
            self.show_login_window()

    def show_setup_master_window(self):
        win = Toplevel(self.root)
        win.title("Buat Master Password")
        self.center_window(win, 420, 260)
        win.configure(bg="#f1f6fb")

        Label(win, text="Buat Master Password", font=("Segoe UI", 11, "bold"), bg="#f1f6fb").pack(pady=(12, 6))
        pwd_var = StringVar()
        Entry(win, textvariable=pwd_var, show="*", font=("Segoe UI", 10)).pack(pady=4, padx=16, fill="x")

        Label(win, text="Konfirmasi Password", bg="#f1f6fb").pack(pady=(6, 4))
        confirm_var = StringVar()
        Entry(win, textvariable=confirm_var, show="*", font=("Segoe UI", 10)).pack(pady=4, padx=16, fill="x")

        Label(win, text="Hint (opsional) - petunjuk bila lupa", bg="#f1f6fb").pack(pady=(8, 4))
        hint_var = StringVar()
        Entry(win, textvariable=hint_var, font=("Segoe UI", 10)).pack(pady=4, padx=16, fill="x")

        def create_and_proceed():
            p1 = pwd_var.get().strip()
            p2 = confirm_var.get().strip()
            hint_text = hint_var.get().strip()
            if not p1:
                messagebox.showwarning("Error", "Master password tidak boleh kosong.")
                return
            if p1 != p2:
                messagebox.showwarning("Error", "Password dan konfirmasi tidak sama.")
                return
            create_config(p1, hint_text)
            messagebox.showinfo("Sukses", "Master password disimpan. Silakan login.")
            win.destroy()
            self.show_login_window()

        ttk.Button(win, text="Buat Master Password", command=create_and_proceed).pack(pady=12)

    def show_login_window(self):
        win = Toplevel(self.root)
        win.title("Login")
        self.center_window(win, 420, 200)
        win.configure(bg="#f1f6fb")

        Label(win, text="Masukkan Master Password", font=("Segoe UI", 11, "bold"), bg="#f1f6fb").pack(pady=(16, 6))
        pwd_var = StringVar()
        e = Entry(win, textvariable=pwd_var, show="*", font=("Segoe UI", 10))
        e.pack(padx=16, fill="x")

        def attempt_login():
            p = pwd_var.get().strip()
            if verify_master(p):
                self.fernet = get_fernet_from_master(p)
                win.destroy()
                self.launch_main_window()
            else:
                messagebox.showerror("Gagal", "Master password salah.")

        btn_frame = Frame(win, bg="#f1f6fb")
        btn_frame.pack(pady=12, fill="x", padx=16)

        ttk.Button(btn_frame, text="Login", command=attempt_login).pack(side="left")
        ttk.Button(btn_frame, text="Lihat Hint", command=lambda: messagebox.showinfo("Hint Master Password", load_hint() or "Belum ada hint yang disimpan.")).pack(side="left", padx=8)

        def reset_vault_from_login():
            if not messagebox.askyesno("Reset Vault", "Semua file konfigurasi, data, dan hint akan dihapus. Lanjutkan?"):
                return
            try:
                if CONFIG_FILE.exists():
                    CONFIG_FILE.unlink()
                if DATA_FILE.exists():
                    DATA_FILE.unlink()
                if HINT_FILE.exists():
                    HINT_FILE.unlink()
            except Exception as e:
                messagebox.showerror("Error", f"Gagal menghapus file: {e}")
                return
            messagebox.showinfo("Reset Berhasil", "Vault berhasil direset. Aplikasi akan ditutup. Jalankan ulang untuk membuat master password baru.")
            # close app
            self.root.destroy()

        ttk.Button(btn_frame, text="Reset Vault", command=reset_vault_from_login).pack(side="right")

        e.bind("<Return>", lambda event: attempt_login())

    def launch_main_window(self):
        self.accounts = load_accounts()
        self.build_main_ui()

    def build_main_ui(self):
        self.root.geometry("860x540")
        header = Label(self.root, text="🔐 VaultKey Password Manager", font=("Segoe UI", 14, "bold"),
                       bg="#e9f1f7", fg="#0078D7")
        header.pack(pady=10)

        # Input form
        form = Frame(self.root, bg="#e9f1f7")
        form.pack(pady=5)
        labels = ["Aplikasi/Situs:", "Username/Email:", "Password:", "Catatan:"]
        self.entries = []

        for i, lbl in enumerate(labels):
            Label(form, text=lbl, bg="#e9f1f7").grid(row=i // 2, column=(i % 2) * 2, sticky="e", padx=5, pady=3)
            ent = Entry(form, width=30, font=("Segoe UI", 10))
            ent.grid(row=i // 2, column=(i % 2) * 2 + 1, padx=5, pady=3)
            self.entries.append(ent)

        ttk.Button(form, text="Tambah Akun", command=self.add_account).grid(row=2, column=1, pady=8)
        ttk.Button(form, text="Clear Form", command=self.clear_form).grid(row=2, column=3, pady=8)

        # Search bar
        search_frame = Frame(self.root, bg="#e9f1f7")
        search_frame.pack(fill="x", padx=12, pady=(6, 8))
        Label(search_frame, text="Cari:", bg="#e9f1f7").pack(side="left")
        self.search_var = StringVar()
        Entry(search_frame, textvariable=self.search_var, width=25).pack(side="left", padx=6)
        ttk.Button(search_frame, text="Cari", command=self.search_accounts).pack(side="left")
        ttk.Button(search_frame, text="Tampilkan Semua", command=self.refresh_table).pack(side="left", padx=6)

        # Table
        cols = ("id", "aplikasi", "username", "password", "catatan")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=15)
        self.tree.heading("aplikasi", text="Aplikasi / Situs")
        self.tree.heading("username", text="Username / Email")
        self.tree.heading("password", text="Password (terenkripsi)")
        self.tree.heading("catatan", text="Catatan")

        self.tree.column("id", width=0, stretch=False)
        self.tree.column("aplikasi", width=200)
        self.tree.column("username", width=180)
        self.tree.column("password", width=240)
        self.tree.column("catatan", width=180)

        self.tree.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # Bottom buttons
        bottom = Frame(self.root, bg="#e9f1f7")
        bottom.pack(fill="x", padx=12, pady=8)
        ttk.Button(bottom, text="Show Password", command=self.show_password).pack(side="left")
        ttk.Button(bottom, text="Copy Password", command=self.copy_password).pack(side="left", padx=6)
        ttk.Button(bottom, text="Hapus", command=self.delete_selected).pack(side="left", padx=6)
        ttk.Button(bottom, text="Export JSON", command=self.export_data).pack(side="right", padx=6)
        ttk.Button(bottom, text="Ganti Master Password", command=self.change_master_password).pack(side="right")

        # Add Reset Vault also in main UI (right side)
        def reset_vault_from_main():
            if not messagebox.askyesno("Reset Vault", "Semua file konfigurasi, data, dan hint akan dihapus. Lanjutkan?"):
                return
            try:
                if CONFIG_FILE.exists():
                    CONFIG_FILE.unlink()
                if DATA_FILE.exists():
                    DATA_FILE.unlink()
                if HINT_FILE.exists():
                    HINT_FILE.unlink()
            except Exception as e:
                messagebox.showerror("Error", f"Gagal menghapus file: {e}")
                return
            messagebox.showinfo("Reset Berhasil", "Vault berhasil direset. Aplikasi akan ditutup. Jalankan ulang untuk membuat master password baru.")
            self.root.destroy()

        ttk.Button(bottom, text="Reset Vault", command=reset_vault_from_main).pack(side="right", padx=6)

        self.refresh_table()

    # ---------- Fitur utama ----------
    def clear_form(self):
        for e in self.entries:
            e.delete(0, END)

    def add_account(self):
        app, user, pw, note = [e.get().strip() for e in self.entries]
        if not app or not user or not pw:
            messagebox.showwarning("Isi dulu", "Isi Aplikasi, Username, dan Password minimal.")
            return
        try:
            enc = encrypt_password(self.fernet, pw)
        except Exception as e:
            messagebox.showerror("Error", f"Gagal enkripsi: {e}")
            return
        entry = {"id": str(uuid.uuid4()), "aplikasi": app, "username": user, "password": enc, "catatan": note}
        self.accounts.append(entry)
        save_accounts(self.accounts)
        messagebox.showinfo("Sukses", "Akun ditambahkan.")
        self.clear_form()
        self.refresh_table()

    def refresh_table(self, rows=None):
        for r in self.tree.get_children():
            self.tree.delete(r)
        rows = rows or self.accounts
        for acc in rows:
            self.tree.insert("", END, values=(acc["id"], acc["aplikasi"], acc["username"], acc["password"], acc.get("catatan", "")))

    def search_accounts(self):
        q = self.search_var.get().strip().lower()
        if not q:
            self.refresh_table()
            return
        filtered = [a for a in self.accounts if q in a["aplikasi"].lower() or q in a["username"].lower()]
        self.refresh_table(filtered)

    def get_selected_account(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Pilih dulu", "Pilih akun dari list.")
            return None
        vals = self.tree.item(sel[0], "values")
        return next((a for a in self.accounts if a["id"] == vals[0]), None)

    def show_password(self):
        acc = self.get_selected_account()
        if not acc: return
        try:
            pw = decrypt_password(self.fernet, acc["password"])
            messagebox.showinfo("Password", f"Username: {acc['username']}\nPassword: {pw}")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal dekripsi: {e}")

    def copy_password(self):
        acc = self.get_selected_account()
        if not acc: return
        try:
            pw = decrypt_password(self.fernet, acc["password"])
            self.root.clipboard_clear()
            self.root.clipboard_append(pw)
            messagebox.showinfo("Copied", "Password disalin ke clipboard.")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal dekripsi: {e}")

    def delete_selected(self):
        acc = self.get_selected_account()
        if not acc: return
        if not messagebox.askyesno("Konfirmasi", f"Hapus akun {acc['aplikasi']} ?"):
            return
        self.accounts = [a for a in self.accounts if a["id"] != acc["id"]]
        save_accounts(self.accounts)
        self.refresh_table()
        messagebox.showinfo("Terhapus", "Akun dihapus.")

    def change_master_password(self):
        win = Toplevel(self.root)
        win.title("Ganti Master Password")
        self.center_window(win, 360, 260)
        win.configure(bg="#f1f6fb")

        Label(win, text="Master Lama:", bg="#f1f6fb").pack(pady=(8, 4))
        old = StringVar(); Entry(win, textvariable=old, show="*").pack(fill="x", padx=12)
        Label(win, text="Master Baru:", bg="#f1f6fb").pack(pady=(8, 4))
        new = StringVar(); Entry(win, textvariable=new, show="*").pack(fill="x", padx=12)
        Label(win, text="Konfirmasi Baru:", bg="#f1f6fb").pack(pady=(8, 4))
        conf = StringVar(); Entry(win, textvariable=conf, show="*").pack(fill="x", padx=12)
        Label(win, text="Hint Baru (opsional):", bg="#f1f6fb").pack(pady=(8, 4))
        new_hint = StringVar(); Entry(win, textvariable=new_hint).pack(fill="x", padx=12)

        def do_change():
            oldp, newp, confp, hintp = old.get().strip(), new.get().strip(), conf.get().strip(), new_hint.get().strip()
            if not verify_master(oldp):
                messagebox.showerror("Error", "Master lama salah."); return
            if not newp or newp != confp:
                messagebox.showwarning("Error", "Konfirmasi tidak sama."); return
            try:
                oldf = get_fernet_from_master(oldp)
                new_salt = generate_salt()
                newf = Fernet(derive_key(newp, new_salt))
                for acc in self.accounts:
                    plain = decrypt_password(oldf, acc["password"])
                    acc["password"] = encrypt_password(newf, plain)
                save_accounts(self.accounts)
                save_json(CONFIG_FILE, {
                    "salt": base64.b64encode(new_salt).decode(),
                    "master_hash": hash_master_password(newp, new_salt),
                    "kdf_iterations": KDF_ITERATIONS
                })
                save_hint(hintp)
                self.fernet = newf
                messagebox.showinfo("Sukses", "Master password diganti.")
                win.destroy()
                self.refresh_table()
            except Exception as e:
                messagebox.showerror("Error", f"Gagal mengganti master password: {e}")

        ttk.Button(win, text="Ganti Password", command=do_change).pack(pady=12)

    def export_data(self):
        desktop = Path.home() / "Desktop"
        out = desktop / f"pwkeeper_backup_{secrets.token_hex(4)}.json"
        save_json(out, self.accounts)
        messagebox.showinfo("Export", f"Backup disimpan ke: {out}")

# ---------- Run ----------
def main():
    root = Tk()
    # keep root hidden until login/setup finish
    root.withdraw()
    app = PasswordKeeperApp(root)
    root.deiconify()
    root.mainloop()

if __name__ == "__main__":
    main()
