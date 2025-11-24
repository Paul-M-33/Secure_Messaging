import pytest
import json
import websockets
import base64
import crypto.cipher as c

SERVER_URI = "ws://localhost:8765"

# -------------------------------
# 1️⃣ Tests Crypto Primitives
# -------------------------------


def test_generate_rsa_keys():
    priv, pub = c.generate_rsa_keys()
    assert priv is not None
    assert pub is not None
    assert isinstance(pub, str)
    assert isinstance(priv, str)


def test_rsa_encrypt_decrypt():
    bob_priv, bob_pub = c.generate_rsa_keys()

    message = "Hello Bob! This is Alice."
    encrypted = c.encrypt_rsa_message(message, bob_pub)
    assert encrypted != message

    decrypted = c.decrypt_rsa_message(encrypted, bob_priv)
    assert decrypted == message


def test_generate_symmetric_keys():
    key = c.generate_symmetric_key()
    assert key is not None
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_aes_encrypt_decrypt():
    key = c.generate_symmetric_key()

    message = "Hello Bob! This is Alice."
    encrypted = c.encrypt_symmetric_message(message, key)
    assert encrypted != message

    decrypted = c.decrypt_symmetric_message(encrypted, key)
    assert decrypted == message


def test_signature():
    priv, pub = c.generate_rsa_keys()

    message = "Hello Bob! This is Alice."
    sig = c.sign_message(message, priv)
    assert sig is not None
    assert isinstance(sig, bytes)

    assert c.verify_signature(message, sig, pub)

# -------------------------------
# 2️⃣ Tests Server Connectivity
# /!\ Server must be running before running these tests
# -------------------------------


@pytest.mark.asyncio
async def test_server_register_and_get_peers():
    """
    Connects to the server, registers a test user, requests peer list, and closes.
    """
    async with websockets.connect(SERVER_URI) as ws:
        # Register test user
        priv, pub = c.generate_rsa_keys()
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
        priv, pub = c.generate_rsa_keys()
        username = "PytestSender"
        await ws.send(json.dumps({
            "type": "register",
            "name": username,
            "pub_key": pub
        }))

        # Receive initial peers
        raw = await ws.recv()

        # Encrypt message and encode as base64
        encrypted_msg = c.encrypt_rsa_message("Test message", pub)
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
        decrypted_msg = c.decrypt_rsa_message(encrypted_bytes, priv)

        assert data_forward["type"] == "forward"
        assert decrypted_msg == "Test message"
