import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def random_bit():
    return bytes ( [ secrets.randbits(1) ] )

def random_challenge(size: int):
    return secrets.token_bytes(size)

def sha256(data: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def sha512(data: bytes):
    digest = hashes.Hash(hashes.SHA512())
    digest.update(data)
    return digest.finalize()

def aes256(data: bytes, key:bytes):
    assert len(key) == 32
    assert len(data) % 16 == 0

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes128(data: bytes, key:bytes):
    assert len(key) == 16
    assert len(data) % 16 == 0

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def pbkdf2(password: bytes, salt: bytes, len: int = 32, iterations: int = 1000000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=len,
        salt=salt,
        iterations=iterations,
    )

    return kdf.derive(password)

def get_bit(data:bytes, pos : int):
    i = pos // 8
    offset = pos % 8
    m = 1 << (7 - offset)

    return bytes( [ ( data[i] & m ) > 0 ] )