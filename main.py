from tkinter import Tk
from pwkeeper_main_ui import PasswordKeeperApp

def main():
    root = Tk()
    root.withdraw()
    app = PasswordKeeperApp(root)
    root.deiconify()
    root.mainloop()

if __name__ == "__main__":
    main()
