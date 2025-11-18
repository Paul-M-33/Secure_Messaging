import pytest
import json
import websockets
import base64
from cipher import generate_keys, encrypt_message, decrypt_message

SERVER_URI = "ws://localhost:8765"

# -------------------------------
# 1️⃣ Tests Crypto Primitives
# -------------------------------


def test_generate_keys():
    priv, pub = generate_keys()
    assert priv is not None
    assert pub is not None
    assert isinstance(pub, str)


def test_encrypt_decrypt():
    alice_priv, alice_pub = generate_keys()
    bob_priv, bob_pub = generate_keys()

    message = "Hello Bob! This is Alice."
    encrypted = encrypt_message(message, bob_pub)
    assert encrypted != message

    decrypted = decrypt_message(encrypted, bob_priv)
    assert decrypted == message

# -------------------------------
# 2️⃣ Tests Server Connectivity
# -------------------------------


@pytest.mark.asyncio
async def test_server_register_and_get_peers():
    """
    Connects to the server, registers a test user, requests peer list, and closes.
    """
    async with websockets.connect(SERVER_URI) as ws:
        # Register test user
        priv, pub = generate_keys()
        await ws.send(json.dumps({
            "type": "register",
            "name": "PytestUser",
            "pub_key": pub
        }))

        # Request peer list
        await ws.send(json.dumps({"type": "get_peers"}))
        raw = await ws.recv()
        data = json.loads(raw)

        assert "type" in data
        assert data["type"] == "peers"
        assert "peers" in data
        assert "pubkeys" in data


@pytest.mark.asyncio
async def test_server_send_message():
    """
    Tests sending an encrypted message to self (loopback) if registered.
    Requires server running.
    """
    async with websockets.connect(SERVER_URI) as ws:
        priv, pub = generate_keys()
        username = "PytestSender"
        await ws.send(json.dumps({
            "type": "register",
            "name": username,
            "pub_key": pub
        }))

        # Receive initial peers
        raw = await ws.recv()

        # Encrypt message and encode as base64
        encrypted_msg = encrypt_message("Test message", pub)
        encrypted_b64 = base64.b64encode(encrypted_msg).decode('ascii')

        # Send message to self
        await ws.send(json.dumps({
            "type": "send",
            "from": username,
            "to": username,
            "payload": encrypted_b64
        }))

        # Receive the forwarded message
        raw_forward = await ws.recv()
        data_forward = json.loads(raw_forward)

        # Decode base64 and decrypt
        encrypted_bytes = base64.b64decode(data_forward["payload"])
        decrypted_msg = decrypt_message(encrypted_bytes, priv)

        assert data_forward["type"] == "forward"
        assert decrypted_msg == "Test message"
