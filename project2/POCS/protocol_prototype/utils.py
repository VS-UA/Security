import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

N = 256

HOST = '127.0.0.1' 
PORT = 55555     

PASSWORD = b'Password'
USERNAME = b'Username'

PC1 = b'Magic server to client constant'
PC2 = b'Pad to make it do more than one iteration'

CS = 16

def random_bit():
    # return bytes( [ random.getrandbits(1) ] )
    return bytes ( [ secrets.randbits(1) ] )

def random_challenge():
    # return os.urandom(CS)
    return secrets.token_bytes(CS)

def sha256(data: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def aes256(data: bytes, key:bytes):
    assert len(key) == 32
    assert len(data) % 16 == 0

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def pdkdf2(password: bytes, salt: bytes, len: int = 32, iterations: int = 10000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=len,
        salt=salt,
        iterations=iterations,
    )

    return kdf.derive(password)

def get_bit(data:bytes, pos : int):
    i = pos // 8
    offset = pos % 8
    m = 1 << (7 - offset)

    # print("\n\nData: ")
    # for my_byte in data:
    #     print(f'{my_byte:0>8b}', end=' ')

    # print (f"\n Bit {pos} = {bytes( [ ( data[i] & m ) > 0 ] )}")
    # print(f"i: {i}, offset: {offset}, m: {m}\n\n")

    return bytes( [ ( data[i] & m ) > 0 ] )