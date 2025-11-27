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
def load_users(path=USERS_FILE):
    """
    Load users from a JSON file.

    Args:
        path (str): Path to the JSON file containing user data. Defaults to USERS_FILE.

    Returns:
        dict: A dictionary mapping usernames to user data.
    """
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def save_users(users, path=USERS_FILE):
    """
    Save users dictionary to a JSON file.

    Args:
        users (dict): Dictionary containing user data.
        path (str): Path to the JSON file to save data. Defaults to USERS_FILE.
    """
    with open(path, "w") as f:
        json.dump(users, f, indent=4)


def hash_password(password, salt):
    """
    Generate a SHA-256 hash of the password concatenated with the salt.

    Args:
        password (str): The user's password.
        salt (str): A random salt.

    Returns:
        str: Hexadecimal string of the hashed password.
    """
    return hashlib.sha256((password + salt).encode()).hexdigest()


# ---------------------------------------------------------
# Pure logic functions
# ---------------------------------------------------------
def validate_login(users, username, password):
    """
    Validate login credentials.

    Args:
        users (dict): Dictionary of all registered users.
        username (str): The username to validate.
        password (str): The password to validate.

    Returns:
        tuple: (success (bool), message (str)). `success` is True if login is valid; otherwise False.
               `message` contains an error message if login failed.
    """
    if not username or not password:
        return False, "Enter username and password."
    if username not in users:
        return False, "Unknown user."
    user = users[username]
    hashed_attempt = hash_password(password, user["salt"])
    if hashed_attempt != user["password_hash"]:
        return False, "Incorrect password."
    return True, ""


def validate_create(users, username, password, confirm):
    """
    Validate data for creating a new account.

    Args:
        users (dict): Dictionary of all registered users.
        username (str): Desired username.
        password (str): Desired password.
        confirm (str): Confirmation of password.

    Returns:
        tuple: (success (bool), message (str)). `success` is True if creation is valid; otherwise False.
               `message` contains an error message if creation failed.
    """
    if not username or not password:
        return False, "Enter username and password."
    if password != confirm:
        return False, "Passwords do not match."
    if username in users:
        return False, "This username is already taken."
    return True, ""


def create_account(users, username, password, path=USERS_FILE):
    """
    Create a new user account and update the users dictionary.

    Args:
        users (dict): Dictionary of all registered users.
        username (str): Username for the new account.
        password (str): Password for the new account.

    Returns:
        dict: Updated users dictionary including the new user.
    """
    salt = os.urandom(16).hex()
    hashed = hash_password(password, salt)

    priv_pem, pub_pem = c.generate_rsa_keys()
    encrypted_priv = c.encrypt_private_key(priv_pem, password)
    users[username] = {
        "salt": salt,
        "password_hash": hashed,
        "encrypted_private_key": encrypted_priv,
        "public_key": base64.b64encode(pub_pem.encode()).decode()
    }
    save_users(users, path)
    return users


# ---------------------------------------------------------
# GUI APPLICATION
# ---------------------------------------------------------
class LoginWindow:
    """
    Tkinter GUI window for SecureChat login and account creation.
    Handles user input, validation, and launching the chat window.
    """

    def __init__(self, master):
        """
        Initialize the login window GUI.

        Args:
            master (tk.Tk): The root Tkinter window.
        """
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
        """
        Toggle between login and account creation modes.
        Updates GUI elements accordingly.
        """
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
        """
        Handle the submit button click.
        Performs login or account creation depending on mode,
        and launches ChatWindow on successful login.
        """
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if self.mode.get() == "login":
            success, msg = validate_login(self.users, username, password)
            if not success:
                messagebox.showerror("Error", msg)
                return

            user = self.users[username]
            priv_pem = c.decrypt_private_key(user["encrypted_private_key"], password)
            public_key = base64.b64decode(user["public_key"])
            private_key = priv_pem.encode()

            # run chat
            self.master.destroy()
            chat_root = tk.Tk()
            chat_root.geometry("480x375")
            ChatWindow(chat_root, username, private_key, public_key)
            chat_root.mainloop()
            return

        else:  # create account
            confirm = self.confirm_entry.get().strip()
            success, msg = validate_create(self.users, username, password, confirm)
            if not success:
                messagebox.showerror("Error", msg)
                return

            self.users = create_account(self.users, username, password)
            messagebox.showinfo("Success", "Account created successfully!")
            self.switch_mode()


# ---------------------------------------------------------
# RUN
# ---------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("280x280")
    LoginWindow(root)
    root.mainloop()
