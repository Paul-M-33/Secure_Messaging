import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
import base64
import datetime
import threading
import json
import asyncio
import websockets
import crypto.cipher as c
import logging

# ---------------------- CONFIG ----------------------
SERVER_URI = "ws://localhost:8765"
LOGFILE = "app.log"

# ---------------------- LOGGING ----------------------
logging.basicConfig(
    filename=LOGFILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
# reduce noisy libs
logging.getLogger("websockets").setLevel(logging.INFO)
logging.getLogger("asyncio").setLevel(logging.INFO)
logger = logging.getLogger(__name__)


class ChatWindow:
    """
    GUI chat window for a single user with encrypted messaging.

    Attributes:
        master (ttk.Tk): The main Tkinter window.
        username (str): The username of the client.
        chat_display (ScrolledText): Widget displaying chat messages.
        entry (ttk.Entry): Widget to input messages.
        send_button (tk.Button): Button to send messages.
        peers (list[str]): List of usernames of connected peers.
        selected_peer (ttk.StringVar): Selected peer for sending messages.
        peer_dropdown (ttk.OptionMenu): Dropdown menu of peers.
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
            master (ttk.Tk): Tkinter root window.
            username (str): Username of this client.
        """
        self.master = master
        self.username = username
        self.master.title(f"SecureChat - {username}")

        # Networking / asyncio
        self.ws = None
        self.loop = asyncio.new_event_loop()

        # Crypto state
        self.priv_key, self.pub_key = c.generate_rsa_keys()
        self.peer_pubkeys = {}
        self.sym_keys = {}

        # Anti-replay
        self.send_counters = {}
        self.last_seen = {}

        # Incoming queue
        self.incoming_msgs = []

        # Peers
        self.peers = []
        self.selected_peer = tk.StringVar(master)
        self.selected_peer.set("No peers yet")

        # Auth mode
        self.auth_mode = tk.BooleanVar(value=False)

        self._build_ui()

        threading.Thread(target=self.run_websocket_loop, daemon=True, name="ws-thread").start()

        # Periodically handle incoming messages
        self.master.after(100, self.process_incoming)

    # ---------------------- UI BUILD HELPERS ----------------------
    def _build_ui(self):
        style = ttk.Style(self.master)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # container
        container = ttk.Frame(self.master, padding=(12, 12, 8, 8))
        container.grid(row=0, column=0, sticky="nsew")
        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(0, weight=1)
        container.rowconfigure(1, weight=1)
        container.columnconfigure(0, weight=1)

        # header
        header = ttk.Label(container, text=f"Messages — {self.username}", font=("Segoe UI", 14, "bold"))
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        # chat display (ScrolledText)
        self.chat_display = scrolledtext.ScrolledText(container, wrap="word", state="disabled", height=18)
        self.chat_display.grid(row=1, column=0, sticky="nsew")

        # bubble/tag styling
        self.chat_display.tag_config("bubble_in",
                                     background="#F3F3F3",
                                     foreground="#222222",
                                     lmargin1=12, lmargin2=20, rmargin=200,
                                     spacing1=4, spacing3=8,
                                     font=("Segoe UI", 10))
        self.chat_display.tag_config("bubble_out",
                                     background="#D6EDFF",
                                     foreground="#222222",
                                     lmargin1=200, lmargin2=20, rmargin=12,
                                     spacing1=4, spacing3=8, justify="right",
                                     font=("Segoe UI", 10))
        self.chat_display.tag_config("timestamp_left",
                                     foreground="gray", font=("Segoe UI", 8), lmargin1=12)
        self.chat_display.tag_config("timestamp_right",
                                     foreground="gray", font=("Segoe UI", 8), justify="right", rmargin=12)

        # controls (peers + auth)
        controls = ttk.Frame(container)
        controls.grid(row=2, column=0, sticky="ew", pady=(8, 6))
        controls.columnconfigure(2, weight=1)

        ttk.Label(controls, text="Send to:").grid(row=0, column=0, padx=(0, 6))
        self.peer_combobox = ttk.Combobox(controls, textvariable=self.selected_peer, state="readonly", width=24)
        self.peer_combobox.grid(row=0, column=1, padx=(0, 12))

        self.auth_chk = ttk.Checkbutton(controls, text="Authenticity", variable=self.auth_mode)
        self.auth_chk.grid(row=0, column=2, sticky="w")

        # bottom: entry + send
        bottom = ttk.Frame(container)
        bottom.grid(row=3, column=0, sticky="ew")
        bottom.columnconfigure(0, weight=1)

        self.entry = ttk.Entry(bottom)
        self.entry.grid(row=0, column=0, sticky="ew", padx=(0, 6), pady=(6, 0))
        self.entry.bind("<Return>", lambda e: self.send_message())
        self.entry.bind("<KeyRelease>", lambda e: self._update_send_state())
        self.entry.focus()

        # send button
        send_button_style = ttk.Style()
        send_button_style.configure("Green.TButton", foreground="black", background="#2ecc71")
        send_button_style.map(
            "Green.TButton",
            background=[
                ("disabled", "#c0c0c0"),   # gray when disabled
                ("active",   "#27ae60"),   # darker green when clicked/hover
                ("!disabled", "#2ecc71")   # normal green
            ]
        )

        self.send_button = ttk.Button(bottom, text="Send", command=self.send_message, style="Green.TButton")
        self.send_button.grid(row=0, column=1, pady=(6, 0))
        # disable initially until text present
        self.send_button.state(["disabled"])

        # status bar (keeps you informed)
        self.status = ttk.Label(self.master, text="Connecting...", anchor="w", relief="sunken")
        self.status.grid(row=1, column=0, sticky="ew", padx=0, pady=(6, 0))

        # context menu
        self._make_context_menu()

    def _make_context_menu(self):
        # simple right-click menu (uses tk menu)
        self._ctx = tk.Menu(self.master, tearoff=0)
        self._ctx.add_command(label="Copy", command=self._ctx_copy)
        self._ctx.add_command(label="Clear chat", command=self._clear_chat)
        # Bind right-click on the ScrolledText widget
        self.chat_display.bind("<Button-3>", self._show_context_menu)

    def _ctx_copy(self):
        try:
            txt = self.chat_display.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.master.clipboard_clear()
            self.master.clipboard_append(txt)
        except Exception:
            pass

    def _show_context_menu(self, event):
        try:
            self._ctx.tk_popup(event.x_root, event.y_root)
        finally:
            self._ctx.grab_release()

    def _clear_chat(self):
        self.chat_display.config(state="normal")
        self.chat_display.delete("1.0", tk.END)
        self.chat_display.config(state="disabled")

    def _update_send_state(self):
        t = self.entry.get().strip()
        if t:
            self.send_button.state(["!disabled"])
        else:
            self.send_button.state(["disabled"])

    # ---------------------- Display / Peer helpers ----------------------

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
        if self.peers:
            self.peer_combobox["values"] = self.peers
            # if previously 'No peers yet', select first
            if self.selected_peer.get() == "No peers yet" or self.selected_peer.get() not in self.peers:
                self.selected_peer.set(self.peers[0])
        else:
            self.peer_combobox["values"] = []
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
        if not text:  # should not happen because button is disabled if no text
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

        # Prepare anti-replay msg_id (simple monotonic counter)
        next_id = self.send_counters.get(to, 1)
        self.send_counters[to] = next_id + 1  # increment for next message

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
            "payload": base64.b64encode(encrypted_payload).decode(),
            "message_id": next_id
        }

        if self.auth_mode.get():
            # to sign, encrypt with user's private key
            signature = c.sign_message(text, next_id, self.priv_key)
            signature_b64 = base64.b64encode(signature).decode()
            msg["signature"] = signature_b64

        asyncio.run_coroutine_threadsafe(self.ws.send(json.dumps(msg)), self.loop)
        # display with local timestamp
        self.display_message(f"{self.username} → {to}", text, timestamp=datetime.datetime.now(), is_outgoing=True)
        self.entry.delete(0, tk.END)

        self._update_send_state()

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
        try:
            async with websockets.connect(SERVER_URI) as ws:
                self.ws = ws
                self.status.config(text="Connected")
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
                        msg_id = data["message_id"]

                        timestamp = datetime.datetime.now()

                        # Anti-replay: msg_id must be present and strictly greater than last_seen
                        if msg_id is None:
                            logger.warning(f"[WARN] no msg_id from {sender}; dropping (anti-replay enforced)")
                            continue

                        last = self.last_seen.get(sender, 0)
                        if not isinstance(msg_id, int):
                            try:
                                msg_id = int(msg_id)
                            except Exception:
                                logger.warning(f"[WARN] invalid msg_id format from {sender}; dropping")
                                continue

                        if msg_id <= last:
                            # replay or out-of-order/duplicate: drop
                            logger.error(f"[REPLAY] dropped message from {sender} with msg_id={msg_id} (last_seen={last})")
                            continue

                        # If we accept this message, update last_seen immediately
                        logger.info(f"[REPLAY] message accepted from {sender} with msg_id={msg_id} (last_seen={last})")
                        self.last_seen[sender] = msg_id
                        
                        # Decipher the message
                        payload_bytes = base64.b64decode(payload)

                        # ensure AES key exists before attempting to decrypt
                        if sender not in self.sym_keys:
                            logger.warning(f"No AES key for {sender} yet — cannot decrypt message msg_id={msg_id}. Dropping for now.")
                            continue

                        try:
                            decrypted = c.decrypt_symmetric_message(payload_bytes, self.sym_keys[sender])
                        except Exception:
                            decrypted = "<Could not decrypt>"
                            timestamp = None

                        # check signature if auth mode is enabled
                        signature_b64 = data.get("signature")
                        if signature_b64:
                            signature = base64.b64decode(signature_b64)
                            try:
                                if not c.verify_signature(decrypted, str(msg_id), signature, self.peer_pubkeys[sender]):
                                    logger.error(f"[ERROR] Signature mismatch from {sender}")
                                    continue  # skip processing this message further
                                logger.info(f"[VALID SIGNATURE] auth mode is active and signature verified for {sender}")
                            except Exception as e:
                                logger.error(f"[ERROR] Signature verification failed for {sender}: {e}")
                                continue

                        self.incoming_msgs.append((sender, decrypted, timestamp))

                    elif t == "aes_key":
                        sender = data["from"]
                        encrypted_key_b64 = data["payload"]
                        encrypted_key = base64.b64decode(encrypted_key_b64)

                        aes_key_b64 = c.decrypt_rsa_message(encrypted_key, self.priv_key)
                        aes_key = base64.b64decode(aes_key_b64)
                        self.sym_keys[sender] = aes_key
        finally:
            # ensure loop is stopped if websocket_main exits
            try:
                if self.loop.is_running():
                    self.loop.call_soon_threadsafe(self.loop.stop)
                    self.status.config(text="Disonnected")
            except Exception:
                pass

    def run_websocket_loop(self):
        """
        Run the asyncio event loop for WebSocket communication in a separate thread.
        """
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.websocket_main())
