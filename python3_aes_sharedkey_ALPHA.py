#!/usr/bin/env python3

import base64
import os
from typing import Literal
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESCipher:
    def __init__(self, key: bytes, mode: Literal['ECB', 'CBC'] = 'ECB'):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")

        self.key = key
        self.block_size = 128  # AES block size in bits
        self.mode_name = mode.upper()

        if self.mode_name == 'ECB':
            self.mode = modes.ECB()
        elif self.mode_name == 'CBC':
            self.iv = os.urandom(16)
            self.mode = modes.CBC(self.iv)
        else:
            raise ValueError("Unsupported mode. Use 'ECB' or 'CBC'.")

        self._cipher = Cipher(algorithms.AES(self.key), self.mode)

    def encrypt(self, raw: str) -> str:
        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(raw.encode()) + padder.finalize()
        encryptor = self._cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        if self.mode_name == 'CBC':
            # Prepend IV to ciphertext for later use
            return base64.b64encode(self.iv + ciphertext).decode()
        else:
            return base64.b64encode(ciphertext).decode()

    def decrypt(self, raw_b64: str) -> str:
        raw_bytes = base64.b64decode(raw_b64)

        if self.mode_name == 'CBC':
            iv = raw_bytes[:16]
            ciphertext = raw_bytes[16:]
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        else:
            ciphertext = raw_bytes
            cipher = self._cipher

        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(self.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()


if __name__ == '__main__':
    key = b'`?.F(fHbN6XK|j!t'
    plaintext = '542#1504891440039'

    print("\n=== ECB MODE ===")
    aes_ecb = AESCipher(key, mode='ECB')
    encrypted_ecb = aes_ecb.encrypt(plaintext)
    print(f'Encrypted (ECB): {encrypted_ecb}')
    decrypted_ecb = aes_ecb.decrypt(encrypted_ecb)
    print(f'Decrypted (ECB): {decrypted_ecb}')
    assert decrypted_ecb == plaintext

    print("\n=== CBC MODE ===")
    aes_cbc = AESCipher(key, mode='CBC')
    encrypted_cbc = aes_cbc.encrypt(plaintext)
    print(f'Encrypted (CBC): {encrypted_cbc}')
    decrypted_cbc = aes_cbc.decrypt(encrypted_cbc)
    print(f'Decrypted (CBC): {decrypted_cbc}')
    assert decrypted_cbc == plaintext
##
##
