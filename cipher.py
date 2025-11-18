# --- CRYPTO HELPERS ---

from cryptidy import asymmetric_encryption, symmetric_encryption


def generate_keys():
    """
    Generate a new RSA key pair.

    Uses a 2048-bit key size for secure asymmetric encryption.

    Returns:
        tuple: (priv_key, pub_key)
            - priv_key: The private key object used for decryption.
            - pub_key: The public key object used for encryption.

    Example:
        priv, pub = generate_keys()
    """
    priv_key, pub_key = asymmetric_encryption.generate_keys(2048)
    return priv_key, pub_key


def encrypt_message(message, pub_key):
    """
    Encrypt a message using the recipient's public key.

    Parameters:
        message (str): The plaintext message to encrypt.
        pub_key: The recipient's public key object.

    Returns:
        str: The encrypted message as a string, ready for transmission.

    Example:
        encrypted = encrypt_message("Hello", recipient_pub_key)
    """
    encrypted_message = asymmetric_encryption.encrypt_message(message, pub_key)
    return encrypted_message


def decrypt_message(encrypted_message, priv_key):
    """
    Decrypt an encrypted message using the recipient's private key.

    Parameters:
        encrypted_message (str): The encrypted message received.
        priv_key: The recipient's private key object.

    Returns:
        str: The original plaintext message.

    Notes:
        - The underlying cryptidy library may include a timestamp in the message;
          this function returns only the original message.

    Example:
        original = decrypt_message(encrypted, my_priv_key)
    """
    timestamp, original_message = asymmetric_encryption.decrypt_message(encrypted_message, priv_key)
    return timestamp, original_message


def generate_symmetric_key():
    key = symmetric_encryption.generate_key(32)  # 256 bits
    return key


def encrypt_symmetric_message(message, key):
    encrypted = symmetric_encryption.encrypt_message(message, key)
    return encrypted


def decrypt_symmetric_message(encrypted, key):
    timestamp, original_message = symmetric_encryption.decrypt_message(encrypted, key)
    return timestamp, original_message
