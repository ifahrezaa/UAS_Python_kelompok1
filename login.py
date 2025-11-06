# Bagian 4 — GUI Login & Setup
from tkinter import *
from tkinter import ttk, messagebox
from pwkeeper_config import *
from pwkeeper_data import *

class LoginSetupUI:
    def _init_(self, app):
        self.app = app

    def center_window(self, win, width, height):
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = (sw - width) // 2
        y = (sh - height) // 2
        win.geometry(f"{width}x{height}+{x}+{y}")

    def show_setup_master_window(self):
        # (kode setup master password dari program asli)
        pass

    def show_login_window(self):
        # (kode login dari program asli)
        pass
# Bagian 4 — GUI Login & Setup
from tkinter import *
from tkinter import ttk, messagebox
from pwkeeper_config import *
from pwkeeper_data import *

class LoginSetupUI:
    def _init_(self, app):
        self.app = app

    def center_window(self, win, width, height):
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = (sw - width) // 2
        y = (sh - height) // 2
        win.geometry(f"{width}x{height}+{x}+{y}")

    def show_setup_master_window(self):
        # (kode setup master password dari program asli)
        pass

    def show_login_window(self):
        # (kode login dari program asli)
        pass