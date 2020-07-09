import base64
import os
import hashlib

from Crypto.Cipher import AES


def evp_bytes_to_key(password, salt, klen=32, ilen=16, msgdgst='md5'):
    '''
    Derive the key and the IV from the given password and salt.

    @param password  The password to use as the seed.
    @param salt      The salt.
    @param klen      The key length.
    @param ilen      The initialization vector length.
    @param msgdgst   The message digest algorithm to use.
    '''
    mdf = getattr(__import__('hashlib', fromlist=[msgdgst]), msgdgst)

    d = d_i = b''
    while len(d) < klen + ilen:
        d_i = mdf(d_i + password + salt).digest()
        d += d_i
    return d[:klen], d[klen:klen+ilen]


def openssl_like_aes256cbc_encrypt(
        password, plaintext, salt=None, b64_process=True, msgdgst='md5'):
    '''
    Encrypt the plaintext using the password using an openssl
    compatible encryption algorithm.
    $ echo -n "message" | openssl enc -e -aes-256-cbc -a -md md5 -salt -pass \
    pass:<password>

    @param password    Password source.
    @param plaintext   Plaintext to encrypt.
    @param salt        Generate 8 bytes of random data as salt if not provided.
    @param b64_process Whether encode the encrypted data in base64.
    @param msgdgst     Message digest algorithm.
    '''
    if not salt:
        salt = os.urandom(8)

    # The secret key to use in the AES cipher must be 16 (AES-128),
    # 24 (AES-192), or 32 (AES-256) bytes long.
    # The IV must be block_size bytes longs.
    key, iv = evp_bytes_to_key(password, salt, klen=32, ilen=AES.block_size,
                               msgdgst=msgdgst)

    # PKCS#7 padding
    # PKCS#5 padding is defined for 8-byte block sizes, PKCS#7 padding would
    # work for any block size from 1 to 255 bytes.
    # AES in CBC mode can only work with data aligned to the 16 byte boundary.
    # The default padding used is PKCS#7.
    padding_len = AES.block_size - (len(plaintext) % AES.block_size)
    padded_plaintext = plaintext + (bytearray([padding_len] * padding_len))

    # Encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # encrypt method expects your input to consist of an integral number of
    # 16-byte blocks (16 is the size of the basic AES block)
    ciphertext = cipher.encrypt(padded_plaintext)

    # Make openssl compatible.
    openssl_ciphertext = b'Salted__' + salt + ciphertext
    return (base64.b64encode(openssl_ciphertext)
            if b64_process else openssl_ciphertext)
