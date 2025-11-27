import base64
import json
import pytest
import websockets
import crypto.cipher as c

SERVER_URI = "ws://localhost:8765"


#######################################################################
# TEST PART 1 — CRYPTOGRAPHIC PRIMITIVES
#######################################################################


def test_generate_rsa_keys():
    """
    Ensure RSA key generation returns valid PEM-formatted strings.
    """
    priv, pub = c.generate_rsa_keys()
    assert priv is not None
    assert pub is not None
    assert isinstance(pub, str)
    assert isinstance(priv, str)


def test_rsa_encrypt_decrypt():
    """
    RSA: message encrypted with a public key must decrypt correctly with
    the corresponding private key.
    """
    bob_priv, bob_pub = c.generate_rsa_keys()

    message = "Hello Bob! This is Alice."
    encrypted = c.encrypt_rsa_message(message, bob_pub)

    assert encrypted != message  # ciphertext must differ

    decrypted = c.decrypt_rsa_message(encrypted, bob_priv)
    assert decrypted == message


def test_generate_symmetric_keys():
    """
    AES-256: ensure generated symmetric key is 32 bytes.
    """
    key = c.generate_symmetric_key()
    assert key is not None
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_aes_encrypt_decrypt():
    """
    AES-GCM encryption/decryption round-trip.
    """
    key = c.generate_symmetric_key()

    message = "Hello Bob! This is Alice."
    encrypted = c.encrypt_symmetric_message(message, key)
    assert encrypted != message

    decrypted = c.decrypt_symmetric_message(encrypted, key)
    assert decrypted == message


#######################################################################
# TEST PART 2 — SIGNATURE SYSTEM
#######################################################################


def test_signature():
    """
    Ensure signatures are generated correctly and validated successfully.
    """
    priv, pub = c.generate_rsa_keys()

    message = "Hello Bob!"
    message_id = "6"
    sig = c.sign_message(message, message_id, priv)

    assert sig is not None
    assert isinstance(sig, bytes)
    assert c.verify_signature(message, message_id, sig, pub)


def test_signature_tampered_message():
    """
    Signature must fail verification if the message content changes.
    """
    priv, pub = c.generate_rsa_keys()

    message = "Hello"
    msg_id = "10"
    sig = c.sign_message(message, msg_id, priv)

    # Tamper the message
    assert c.verify_signature("HELLO", msg_id, sig, pub) is False


def test_signature_wrong_key():
    """
    Signature must fail verification if validated with a different public key.
    """
    priv1, pub1 = c.generate_rsa_keys()
    priv2, pub2 = c.generate_rsa_keys()

    sig = c.sign_message("Hello", "5", priv1)

    assert c.verify_signature("Hello", "5", sig, pub2) is False


#######################################################################
# TEST PART 3 — ANTI-REPLAY PROTECTION
#######################################################################


def anti_replay_accepts(last_seen, incoming_id) -> bool:
    """
    Helper to simulate the same anti-replay logic used in the GUI.
    """
    if incoming_id is None:
        return False
    try:
        incoming_id = int(incoming_id)
    except:
        return False
    return incoming_id > last_seen


def test_anti_replay_detection():
    """
    Anti-replay: message IDs must be strictly increasing.
    """
    last_seen = 5

    # valid new message
    assert anti_replay_accepts(last_seen, 6) is True

    # replay (same ID)
    assert anti_replay_accepts(last_seen, 5) is False

    # replay (older ID)
    assert anti_replay_accepts(last_seen, 3) is False

    # invalid (not numeric)
    assert anti_replay_accepts(last_seen, "abc") is False

    # missing ID
    assert anti_replay_accepts(last_seen, None) is False


#######################################################################
# TEST PART 4 — PRIVATE KEY PROTECTION & PASSWORD SECURITY
#######################################################################


def test_private_key_encryption_cycle():
    """
    Private key encrypted with password must decrypt correctly with the same password.
    """
    password = "SuperSecret!"
    priv_pem, pub_pem = c.generate_rsa_keys()

    encrypted = c.encrypt_private_key(priv_pem, password)
    decrypted = c.decrypt_private_key(encrypted, password)

    assert decrypted == priv_pem


def test_private_key_wrong_password():
    """
    Attempting to decrypt private key with the wrong password must fail.
    """
    password = "CorrectPassword123"
    wrong_password = "WrongPass"

    priv_pem, pub_pem = c.generate_rsa_keys()
    encrypted = c.encrypt_private_key(priv_pem, password)

    with pytest.raises(Exception):
        c.decrypt_private_key(encrypted, wrong_password)


def test_password_hash_stability():
    """
    Same password + same salt must yield identical hashes.
    """
    from main import hash_password

    pwd = "UserPassword"
    salt = "abcdef123456"

    h1 = hash_password(pwd, salt)
    h2 = hash_password(pwd, salt)
    assert h1 == h2


def test_password_hash_variation():
    """
    Same password with different salts must produce different hashes.
    """
    from main import hash_password

    pwd = "UserPassword"
    salt1 = "abcdef"
    salt2 = "123456"

    assert hash_password(pwd, salt1) != hash_password(pwd, salt2)


#######################################################################
# TEST PART 5 — AES KEY EXCHANGE WORKFLOW (Alice → Bob)
#######################################################################


def test_aes_key_exchange_workflow():
    """
    Simulates Alice encrypting an AES key with Bob's RSA public key.
    Bob must be able to recover the AES key.
    """
    # Bob generates RSA keys
    bob_priv, bob_pub = c.generate_rsa_keys()

    # Alice generates AES key
    aes_key = c.generate_symmetric_key()
    aes_key_b64 = base64.b64encode(aes_key).decode()

    # Alice encrypts AES key with Bob's public key
    encrypted_key = c.encrypt_rsa_message(aes_key_b64, bob_pub)

    # Bob decrypts
    decrypted_b64 = c.decrypt_rsa_message(encrypted_key, bob_priv)
    decrypted_key = base64.b64decode(decrypted_b64)

    assert decrypted_key == aes_key


def test_message_round_trip():
    """
    AES encryption/decryption of a message using a shared symmetric key.
    """
    key = c.generate_symmetric_key()

    plaintext = "Hello Bob!"
    encrypted = c.encrypt_symmetric_message(plaintext, key)
    decrypted = c.decrypt_symmetric_message(encrypted, key)

    assert decrypted == plaintext


#######################################################################
# TEST PART 6 — SERVER CONNECTIVITY (requires running server)
#######################################################################


@pytest.mark.asyncio
async def test_server_register_and_get_peers():
    """
    Connects to the server, registers a test user, requests peer list, and verifies response format.
    Server must be running.
    """
    async with websockets.connect(SERVER_URI) as ws:
        priv, pub = c.generate_rsa_keys()

        # Register user
        await ws.send(json.dumps({
            "type": "register",
            "name": "PytestUser",
            "pub_key": pub
        }))

        # Request peer list
        await ws.send(json.dumps({"type": "get_peers"}))
        raw = await ws.recv()
        data = json.loads(raw)

        assert data["type"] == "peers"
        assert "peers" in data
        assert "pubkeys" in data


@pytest.mark.asyncio
async def test_server_send_message():
    """
    Sends an encrypted message to self (loopback).
    Ensures server forwards messages without modification.
    Server must be running.
    """
    async with websockets.connect(SERVER_URI) as ws:
        priv, pub = c.generate_rsa_keys()
        username = "PytestSender"

        # Register username
        await ws.send(json.dumps({
            "type": "register",
            "name": username,
            "pub_key": pub
        }))

        # Receive peers update
        await ws.recv()

        # Encrypt message
        encrypted_msg = c.encrypt_rsa_message("Test message", pub)
        encrypted_b64 = base64.b64encode(encrypted_msg).decode("ascii")

        # Send to self
        await ws.send(json.dumps({
            "type": "send",
            "from": username,
            "to": username,
            "payload": encrypted_b64,
            "message_id": "1"
        }))

        # Receive forwarded message
        raw_forward = await ws.recv()
        data_forward = json.loads(raw_forward)

        # Decrypt
        encrypted_bytes = base64.b64decode(data_forward["payload"])
        decrypted_msg = c.decrypt_rsa_message(encrypted_bytes, priv)

        assert data_forward["type"] == "forward"
        assert decrypted_msg == "Test message"
