# --- CRYPTO HELPERS ---

import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ============================================================
# RSA KEY GENERATION
# ============================================================


def generate_rsa_keys():
    """
    Generate a new RSA key pair.

    Uses a 2048-bit key size for secure asymmetric encryption.

    Returns:
        tuple: (private_key_pem, public_key_pem)
            - private_key_pem: The private key object used for decryption.
            - public_key_pem: The public key object used for encryption.

    Example:
        priv, pub = generate_keys()
    """
    key = RSA.generate(2048)
    private_key_pem = key.export_key().decode()
    public_key_pem = key.publickey().export_key().decode()
    return private_key_pem, public_key_pem

# ============================================================
# RSA ENCRYPT / DECRYPT
# ============================================================


def encrypt_rsa_message(message: str, public_key_pem: str) -> bytes:
    """
    Encrypt a message using the recipient's public key.

    Parameters:
        message (str): The plaintext message to encrypt.
        public_key_pem (str): The recipient's public key object.

    Returns:
        bytes: The encrypted message.

    Example:
        encrypted = encrypt_message("Hello", recipient_pub_key)
    """
    message = message.encode()
    pubkey = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pubkey)
    encrypted = cipher.encrypt(message)
    return encrypted


def decrypt_rsa_message(ciphertext: bytes, private_key_pem: str) -> bytes:
    """
    Decrypt an encrypted message using the recipient's private key.

    Parameters:
        ciphertext (bytes): The encrypted message received.
        priv_key_pem (str): The recipient's private key object.

    Returns:
        bytes: The original plaintext message.

    Example:
        original = decrypt_message(encrypted, my_priv_key)
    """
    prikey = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(prikey)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode()

# ============================================================
# AES SYMMETRIC KEY GENERATION
# ============================================================


def generate_symmetric_key():
    """
    Generate a new AES key.

    Uses a 256-bit key size for secure symmetric encryption.

    Returns:
        key (bytes): The symmetric key object used for encryption.
    """
    return get_random_bytes(32)  # AES-256

# ============================================================
# AES ENCRYPT / DECRYPT
# ============================================================


def encrypt_symmetric_message(message: str, key: bytes) -> bytes:
    """
    Encrypt a message using the AES key.

    Parameters:
        message (str): The plaintext message to encrypt.
        key (bytes): The private key object.

    Returns:
        bytes: The encrypted message.

    Example:
        encrypted = encrypt_message("Hello", key)
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())

    data = cipher.nonce + tag + ciphertext
    return base64.b64encode(data)


def decrypt_symmetric_message(ciphertext_b64: str, key: bytes) -> str:
    """
    Decrypt an encrypted message using the AES private key.

    Parameters:
        ciphertext_b64 (str): The encrypted message received.
        key (bytes): The key object used to cipher the message.

    Returns:
        str: The original plaintext message.
    """
    raw = base64.b64decode(ciphertext_b64)

    nonce = raw[:16]
    tag = raw[16:32]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    plaintext = cipher.decrypt_and_verify(raw[32:], tag)
    return plaintext.decode()

# ============================================================
# RSA SIGNATURES
# ============================================================


def sign_message(message: str, msg_id: str, private_key_pem: str) -> bytes:
    """
    Sign a message using the private key.

    Parameters:
        message (str): The message to sign.
        msg_id (int): The message ID.
        private_key_pem (str): The private key object.

    Returns:
        str: The signature of the message ID concatenated with the message.
    """
    payload = f"{msg_id}:{message}"
    message_to_sign = payload.encode()
    priv = RSA.import_key(private_key_pem)
    h = SHA256.new(message_to_sign)
    signature = pkcs1_15.new(priv).sign(h)
    return signature


def verify_signature(message: str, msg_id: str, signature: str, public_key_pem: str) -> bool:
    """
    Verify the signature of a message using the public key.

    Parameters:
        message (str): The message to verify.
        msg_id (int): The message ID.
        signature (str): The signature of the message.
        public_key_pem (str): The public key object.

    Returns:
        bool: True if the signature is valid, raises an exception otherwise.
    """
    payload = f"{msg_id}:{message}"
    message_to_verify = payload.encode()
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(message_to_verify)

    try:
        pkcs1_15.new(key).verify(h, signature)
        return True

    except (ValueError, TypeError):
        print("The signature is not valid.")
        return False
