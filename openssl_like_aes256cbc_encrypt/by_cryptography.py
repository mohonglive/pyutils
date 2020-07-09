import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def openssl_like_aes256cbc_pbkdf2_encrypt(
        password, plaintext, salt=None, iterations=100000, b64_process=True,
        msgdgst='sha256'):
    '''
    Encrypt the plaintext using the password using an openssl
    compatible encryption algorithm.
    $ echo -n "message" | openssl enc -e -aes-256-cbc -a -md sha256 -salt \
    -pass pass:<password> -pbkdf2 -iter 100000

    @param password    Password source.
    @param plaintext   Plaintext to encrypt.
    @param salt        Generate 8 bytes of random data as salt if not provided.
    @param iterations  iter count
    @param b64_process Whether encode the encrypted data in base64.
    @param msgdgst     Message digest algorithm.
    '''
    if not salt:
        salt = os.urandom(8)
    elif len(salt) != 8:
        raise ValueError('length of salt must be 8.')

    mdf = getattr(__import__('cryptography.hazmat.primitives.hashes',
                             fromlist=[msgdgst.upper()]), msgdgst.upper())

    kdf = PBKDF2HMAC(algorithm=mdf(), length=48, salt=salt,
                     iterations=iterations, backend=default_backend())
    key = kdf.derive(password)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    encryptor = Cipher(
        algorithms.AES(key[:32]), modes.CBC(key[32:48]), default_backend()
    ).encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    openssl_ciphertext = b'Salted__' + salt + ciphertext
    return (base64.b64encode(openssl_ciphertext)
            if b64_process else openssl_ciphertext)
