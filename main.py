import tkinter as tk
from chat_window.gui import LoginWindow

# ---------------------------------------------------------
# RUN
# ---------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("280x280")
    LoginWindow(root)
    root.mainloop()
