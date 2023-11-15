
##
## https://gist.github.com/tcitry/df5ee377ad112d7637fe7b9211e6bc83
##

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from django.utils.encoding import force_bytes, force_text

SECRET_KEY = "hellomotherfucker"
value = force_bytes("12345678901234567890")

backend = default_backend()
key = force_bytes(base64.urlsafe_b64encode(force_bytes(SECRET_KEY))[:32])


class Crypto:

    def __init__(self):
        self.encryptor = Cipher(algorithms.AES(key), modes.ECB(), backend).encryptor()
        self.decryptor = Cipher(algorithms.AES(key), modes.ECB(), backend).decryptor()

    def encrypt(self):
        padder = padding.PKCS7(algorithms.AES(key).block_size).padder()
        padded_data = padder.update(value) + padder.finalize()
        encrypted_text = self.encryptor.update(padded_data) + self.encryptor.finalize()
        return encrypted_text

    def decrypt(self, value):
        padder = padding.PKCS7(algorithms.AES(key).block_size).unpadder()
        decrypted_data = self.decryptor.update(value)
        unpadded = padder.update(decrypted_data) + padder.finalize()
        return unpadded


if __name__ == '__main__':
    print('>>>>>>>>>>>')
    crypto = Crypto()
    text = force_text(base64.urlsafe_b64encode(crypto.encrypt()))
    print(text)
    print('<<<<<<<<<<<<<')
    text = force_text(crypto.decrypt(base64.urlsafe_b64decode(text)))
    print(text)

##
##
