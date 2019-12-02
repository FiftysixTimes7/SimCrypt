import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

__version__ = '0.1.0'


def x25519_key_gen():
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    return private, public.hex().strip()


def x25519_key_derive(private, peer):
    peer_public = X25519PublicKey.from_public_bytes(
        bytes.fromhex(peer.strip()))
    shared = private.exchange(peer_public)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        info=b'exchange',
        backend=default_backend()
    ).derive(shared)
    return derived_key.hex().strip()


def aes128_encrypt(password: str, data: str):
    key = base64.encodebytes(PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        iterations=10,
        backend=default_backend()
    ).derive(password.encode()))
    f = Fernet(key)
    token = f.encrypt(data.encode())
    return token.strip()


def aes128_decrypt(password: str, token: str):
    key = base64.encodebytes(PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        iterations=10,
        backend=default_backend()
    ).derive(password.encode()))
    f = Fernet(key)
    data = f.decrypt(token.encode())
    return data


def base64_encode(data: str):
    return base64.encodebytes(data.encode()).decode().strip()


def base64_decode(data: str):
    return base64.decodebytes(data.encode()).decode()
