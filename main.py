import tkinter as tk
from tkinter import messagebox
import json
import os
import hashlib
import base64

from chat_window.gui import ChatWindow
import crypto.cipher as c


USERS_FILE = "users.json"


# ---------------------------------------------------------
# Utility functions
# ---------------------------------------------------------
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)


def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()


# ---------------------------------------------------------
# GUI APPLICATION
# ---------------------------------------------------------
class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("SecureChat Login")
        self.users = load_users()

        # mode: "login" or "create"
        self.mode = tk.StringVar(value="login")

        # title
        self.title_label = tk.Label(master, text="Login", font=("Segoe UI", 14, "bold"))
        self.title_label.pack(pady=10)

        # username
        tk.Label(master, text="Username:").pack()
        self.username_entry = tk.Entry(master, width=30)
        self.username_entry.pack(pady=5)

        # password
        tk.Label(master, text="Password:").pack()
        self.password_entry = tk.Entry(master, width=30, show="*")
        self.password_entry.pack(pady=5)

        # confirm password (hidden except in create mode)
        self.confirm_label = tk.Label(master, text="Confirm password:")
        self.confirm_entry = tk.Entry(master, width=30, show="*")

        # submit button
        self.submit_button = tk.Button(master, text="Login", command=self.handle_submit)
        self.submit_button.pack(pady=10)

        # switch mode link
        self.switch_link = tk.Button(
            master, text="Create account", fg="blue", bd=0, command=self.switch_mode
        )
        self.switch_link.pack()

    # -----------------------------------------------------
    def switch_mode(self):
        if self.mode.get() == "login":
            # switch to create
            self.mode.set("create")
            self.title_label.config(text="Create Account")
            self.submit_button.config(text="Create account")
            self.switch_link.config(text="Back to login")

            self.confirm_label.pack()
            self.confirm_entry.pack(pady=5)

        else:
            # switch to login
            self.mode.set("login")
            self.title_label.config(text="Login")
            self.submit_button.config(text="Login")
            self.switch_link.config(text="Create account")

            self.confirm_label.pack_forget()
            self.confirm_entry.pack_forget()

    # -----------------------------------------------------
    def handle_submit(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Enter username and password.")
            return

        # -------------------------------------------------
        # LOGIN MODE
        # -------------------------------------------------
        if self.mode.get() == "login":

            if username not in self.users:
                messagebox.showerror("Error", "Unknown user.")
                return

            # verify password
            user = self.users[username]
            salt = user["salt"]
            hashed_attempt = hash_password(password, salt)

            if hashed_attempt != user["password_hash"]:
                messagebox.showerror("Error", "Incorrect password.")
                return

            # load and decrypt private key
            encrypted_priv = user["encrypted_private_key"]
            priv_pem = c.decrypt_private_key(encrypted_priv, password)

            # load public key
            public_key = base64.b64decode(user["public_key"])

            # convert PEM (string) to bytes so ChatWindow can import it
            private_key = priv_pem.encode()

            # run chat
            self.master.destroy()
            chat_root = tk.Tk()
            chat_root.geometry("480x375")
            ChatWindow(chat_root, username, private_key, public_key)
            chat_root.mainloop()
            return

        # -------------------------------------------------
        # CREATE ACCOUNT MODE
        # -------------------------------------------------
        confirm = self.confirm_entry.get().strip()

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        if username in self.users:
            messagebox.showerror("Error", "This username is already taken.")
            return

        # generate salt + hashed password
        salt = os.urandom(16).hex()
        hashed = hash_password(password, salt)

        # generate fresh RSA keys
        priv_pem, pub_pem = c.generate_rsa_keys()

        # encrypt private key using user's password
        encrypted_priv = c.encrypt_private_key(priv_pem, password)

        # store public key as plain PEM (base64 for JSON)
        self.users[username] = {
            "salt": salt,
            "password_hash": hashed,
            "encrypted_private_key": encrypted_priv,
            "public_key": base64.b64encode(pub_pem.encode()).decode()
        }

        save_users(self.users)
        messagebox.showinfo("Success", "Account created successfully!")

        # return to login
        self.switch_mode()


# ---------------------------------------------------------
# RUN
# ---------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("280x280")
    LoginWindow(root)
    root.mainloop()
