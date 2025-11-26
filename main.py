import tkinter as tk
from chat_window.gui import ChatWindow

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Login")

    tk.Label(root, text="Enter username:").pack(padx=10, pady=10)

    username_entry = tk.Entry(root, width=35)
    username_entry.pack(padx=10, pady=5)

    def start_chat():
        """
        Callback for the login button. Starts the chat window for the entered username.
        """
        name = username_entry.get().strip()
        if not name:
            return
        root.destroy()  # close login window
        chat_root = tk.Tk()
        chat_root.geometry("720x560")
        ChatWindow(chat_root, name)
        chat_root.mainloop()

    tk.Button(root, text="Connect", command=start_chat).pack(pady=10)

    root.mainloop()


# TODO : persistent keys, modular GUI, group CHAT, avatars in connection window ?