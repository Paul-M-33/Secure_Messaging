import tkinter as tk
from tkinter import scrolledtext
import base64
import datetime
import threading
import json
import asyncio
import websockets
import cipher as c


SERVER_URI = "ws://localhost:8765"  # relay server


class ChatWindow:
    """
    GUI chat window for a single user with encrypted messaging.

    Attributes:
        master (tk.Tk): The main Tkinter window.
        username (str): The username of the client.
        chat_display (ScrolledText): Widget displaying chat messages.
        entry (tk.Entry): Widget to input messages.
        send_button (tk.Button): Button to send messages.
        peers (list[str]): List of usernames of connected peers.
        selected_peer (tk.StringVar): Selected peer for sending messages.
        peer_dropdown (tk.OptionMenu): Dropdown menu of peers.
        ws (websockets.WebSocketClientProtocol): WebSocket connection.
        loop (asyncio.AbstractEventLoop): Event loop for async tasks.
        priv_key, pub_key: User's asymmetric key pair.
        peer_pubkeys (dict): Mapping peer username → public key.
        incoming_msgs (list[tuple[str, str]]): Queue of received messages.
    """
    def __init__(self, master, username):
        """
        Initialize the chat window GUI and network/crypto setup.

        Args:
            master (tk.Tk): Tkinter root window.
            username (str): Username of this client.
        """
        self.master = master
        self.master.title(f"Chat - {username}")
        self.username = username

        # --- CHAT DISPLAY ---
        self.chat_display = scrolledtext.ScrolledText(master, width=60, height=20, state="disabled")
        self.chat_display.pack(padx=10, pady=10)

        # --- BUBBLE STYLES ---

        self.chat_display.tag_config("bubble_in", 
                                     background="#E6E6E6", foreground="black",
                                     lmargin1=10, lmargin2=20,
                                     rmargin=150,
                                     spacing3=5,
                                     wrap="word"
                                     )

        self.chat_display.tag_config("bubble_out", 
                                     background="#CDE8FF", foreground="black",
                                     lmargin1=150, lmargin2=20,
                                     rmargin=10,
                                     spacing3=5,
                                     justify="right",
                                     wrap="word"
                                     )

        self.chat_display.tag_config("timestamp_left",
                                     foreground="gray", font=("Arial", 8),
                                     lmargin1=12,
                                     lmargin2=20
                                     )

        self.chat_display.tag_config("timestamp_right",
                                     foreground="gray", font=("Arial", 8),
                                     justify="right",
                                     rmargin=12
                                     )

        # --- MESSAGE ENTRY ---
        entry_frame = tk.Frame(master)
        entry_frame.pack(pady=5)

        self.entry = tk.Entry(entry_frame, width=40)
        self.entry.pack(side=tk.LEFT, padx=(10, 5))
        self.entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = tk.Button(entry_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT)

        # --- PEER SELECTION (DROPDOWN) ---
        self.peers = []   # list of names
        self.selected_peer = tk.StringVar(master)
        self.selected_peer.set("No peers yet")

        peer_frame = tk.Frame(master)
        peer_frame.pack(pady=5)

        tk.Label(peer_frame, text="Send to:").pack(side=tk.LEFT, padx=5)
        self.peer_dropdown = tk.OptionMenu(peer_frame, self.selected_peer, [])
        self.peer_dropdown.pack(side=tk.LEFT, padx=5)

        # --- NETWORK VARIABLES ---
        self.ws = None
        self.loop = asyncio.new_event_loop()

        # --- CRYPTO ---
        self.priv_key, self.pub_key = c.generate_rsa_keys()
        self.peer_pubkeys = {}
        # AES key per peer
        self.sym_keys = {}

        # auth mode
        self.auth_mode = tk.BooleanVar(value=False)

        auth_frame = tk.Frame(master)
        auth_frame.pack(pady=5)

        tk.Checkbutton(auth_frame, text="Authenticity mode", variable=self.auth_mode).pack()

        # Start WebSocket in background thread
        threading.Thread(target=self.run_websocket_loop, daemon=True).start()

        # Periodically check incoming messages
        self.master.after(100, self.process_incoming)
        self.incoming_msgs = []

    # --- GUI HELPERS ---

    def display_message(self, sender, text, timestamp, is_outgoing):
        """
        Display message using bubble-style layout.
        Incoming on left (light gray)
        Outgoing on right (light blue)

        Args:
            sender (str): Name of the message sender.
            text (str): Message content.
            timestamp (datetime): Timestamp of the message.
            is_outgoing (bool): Whether the message is outgoing or incoming.
        """

        self.chat_display.config(state="normal")

        # Determine message type
        bubble_tag = "bubble_out" if is_outgoing else "bubble_in"
        time_tag = "timestamp_right" if is_outgoing else "timestamp_left"

        # Format timestamp
        if timestamp:
            time_str = timestamp.strftime("%H:%M")
        else:
            time_str = ""

        # Insert bubble
        # Add spacing before bubble
        self.chat_display.insert(tk.END, "\n")

        # Insert bubble text
        bubble_text = f"{sender}:\n{text}\n"
        self.chat_display.insert(tk.END, bubble_text, bubble_tag)

        # Insert timestamp aligned properly
        self.chat_display.insert(tk.END, time_str + "\n", time_tag)

        self.chat_display.config(state="disabled")
        self.chat_display.yview(tk.END)

    def update_peer_dropdown(self):
        """
        Update the dropdown menu of peers based on the current peer list.
        """
        menu = self.peer_dropdown["menu"]
        menu.delete(0, "end")
        for peer in self.peers:
            menu.add_command(label=peer, command=lambda p=peer: self.selected_peer.set(p))
        if self.peers:
            self.selected_peer.set(self.peers[0])
        else:
            self.selected_peer.set("No peers yet")

    # --- SEND MESSAGE ---

    def send_message(self):
        """
        Encrypt and send a message to the selected peer.

        Raises:
            Displays a SYSTEM message if:
                - No text is entered
                - No recipient is selected
                - No public key exists for the recipient
        """
        text = self.entry.get().strip()
        to = self.selected_peer.get()
        if not text:
            self.display_message("SYSTEM", "No message entered.", None, True)
            return
        if to == "No peers yet":
            self.display_message("SYSTEM", "No recipient available.", None, True)
            return

        # Ensure we know recipient's public key (we need it to send AES key)
        if to not in self.peer_pubkeys:
            self.display_message("SYSTEM", f"No public key for {to}", None, True)
            return

        # If no symmetric key yet, create one and send it encrypted with recipient RSA pubkey
        if to not in self.sym_keys:
            aes_key = c.generate_symmetric_key()
            self.sym_keys[to] = aes_key

            aes_key_b64 = base64.b64encode(aes_key).decode()
            encrypted_key = c.encrypt_rsa_message(aes_key_b64, self.peer_pubkeys[to])

            # base64 encode RSA output → string for JSON
            encrypted_key_b64 = base64.b64encode(encrypted_key).decode()

            awaitable = self.ws.send(json.dumps({
                "type": "aes_key",
                "from": self.username,
                "to": to,
                "payload": encrypted_key_b64
            }))
            asyncio.run_coroutine_threadsafe(awaitable, self.loop)

        # Now encrypt the message with AES and send
        aes_key_for_peer = self.sym_keys.get(to)
        if aes_key_for_peer is None:
            # Shouldn't happen because we created it above, but guard anyway
            self.display_message("SYSTEM", f"No AES key for {to}", None, True)
            return

        encrypted_payload = c.encrypt_symmetric_message(text, aes_key_for_peer)

        msg = {
            "type": "send",
            "from": self.username,
            "to": to,
            "payload": base64.b64encode(encrypted_payload).decode()
        }

        if self.auth_mode.get():
            # to sign, encrypt with user's private key
            signature = c.sign_message(text, self.priv_key)
            signature_b64 = base64.b64encode(signature).decode()
            msg["signature"] = signature_b64

        asyncio.run_coroutine_threadsafe(self.ws.send(json.dumps(msg)), self.loop)
        # display with local timestamp
        self.display_message(f"{self.username} (to {to})", text, timestamp=datetime.datetime.now(), is_outgoing=True)
        self.entry.delete(0, tk.END)

    # --- RECEIVE ---

    def process_incoming(self):
        """
        Process all messages in the incoming queue and display them.

        Decrypts each message using the user's private key and appends it to the chat display.
        Runs periodically using Tkinter's after method.
        """
        while self.incoming_msgs:
            sender, text, timestamp = self.incoming_msgs.pop(0)
            self.display_message(sender, text, timestamp, is_outgoing=False)
        self.master.after(100, self.process_incoming)

    # --- WEBSOCKET BACKGROUND TASKS ---

    async def websocket_main(self):
        """
        Main asynchronous WebSocket routine.

        - Connects to the server
        - Registers the username and public key
        - Requests the initial peer list
        - Receives updates and forwarded messages
        - Decrypts incoming messages before queuing them for display
        """
        async with websockets.connect(SERVER_URI) as ws:
            self.ws = ws
            await ws.send(json.dumps({"type": "register", "name": self.username, "pub_key": self.pub_key}))
            await ws.send(json.dumps({"type": "get_peers"}))

            async for raw in ws:
                data = json.loads(raw)
                t = data.get("type")

                if t == "peers":
                    self.peers = [p for p in data["peers"] if p != self.username]
                    self.peer_pubkeys = data.get("pubkeys", {})
                    self.master.after(0, self.update_peer_dropdown)

                elif t == "forward":
                    sender = data["from"]
                    payload = data["payload"]

                    # Decipher the message
                    payload_bytes = base64.b64decode(payload)
                    try:
                        decrypted = c.decrypt_symmetric_message(payload_bytes, self.sym_keys[sender])
                        timestamp = datetime.datetime.now()
                    except Exception:
                        decrypted = "<Could not decrypt>"
                        timestamp = None

                    # check signature if auth mode is enabled
                    signature_b64 = data.get("signature")
                    if signature_b64:
                        signature = base64.b64decode(signature_b64)
                        try:
                            if not c.verify_signature(decrypted, signature, self.peer_pubkeys[sender]):
                                print(f"[WARNING] Signature mismatch from {sender}")
                                continue  # skip processing this message further
                            print(f"[VALID SIGNATURE] auth mode is active and signature verified for {sender}")
                        except Exception as e:
                            print(f"[ERROR] Signature verification failed for {sender}: {e}")
                            continue

                    self.incoming_msgs.append((sender, decrypted, timestamp))
                
                elif t == "aes_key":
                    sender = data["from"]
                    encrypted_key_b64 = data["payload"]
                    encrypted_key = base64.b64decode(encrypted_key_b64)

                    aes_key_b64 = c.decrypt_rsa_message(encrypted_key, self.priv_key)
                    aes_key = base64.b64decode(aes_key_b64)
                    self.sym_keys[sender] = aes_key

    def run_websocket_loop(self):
        """
        Run the asyncio event loop for WebSocket communication in a separate thread.
        """
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.websocket_main())


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
        ChatWindow(chat_root, name)
        chat_root.mainloop()

    tk.Button(root, text="Connect", command=start_chat).pack(pady=10)

    root.mainloop()
