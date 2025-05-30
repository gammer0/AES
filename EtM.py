
from HMAC import HMAC
from CBC_AES import CBC_AES
from CTR_AES import CTR_AES


class EtM:
    def __init__(self, safetyPar, mode='CBC'):
        self.safetyPar = safetyPar
        self.mode = mode
        self.hmac = HMAC(safetyPar)

    def encrypt(self, key, message, iv=None):
        if not isinstance(key, tuple) or len(key) != 2:
            raise ValueError("Key must be a tuple of two byte strings.")
        if not isinstance(message, bytes):
            raise TypeError("Message must be of type bytes.")

        aes = CBC_AES(key[0]) if self.mode == 'CBC' else CTR_AES(key[0])
        ciphertext, iv = aes.Encrypt(message, iv)

        hmac_value = self.hmac.Mac(key[1], ciphertext)

        return ciphertext, hmac_value, iv
    
    def decrypt(self, key, ciphertext, hmac_value, iv):
        if not isinstance(key, tuple) or len(key) != 2:
            raise ValueError("Key must be a tuple of two byte strings.")
        if not isinstance(ciphertext, bytes):
            raise TypeError("Ciphertext must be of type bytes.")
        if not isinstance(hmac_value, bytes):
            raise TypeError("HMAC value must be of type bytes.")
        if not isinstance(iv, bytes):
            raise TypeError("IV must be of type bytes.")

        aes = CBC_AES(key[0]) if self.mode == 'CBC' else CTR_AES(key[0])
        decrypted_message = aes.Decrypt(ciphertext, iv)

        if not self.hmac.Verify(key[1], ciphertext, hmac_value):
            raise ValueError("HMAC verification failed. Data integrity compromised.")

        return decrypted_message

if __name__ == "__main__":

    key = (bytes.fromhex("000102030405060708090A0B0C0D0E0F"), bytes.fromhex("101112131415161718191A1B1C1D1E1F"))
    x = EtM(256, mode='CBC')  # or mode='CTR' for CTR mode
    message = b"This is a test message for EtM mode encryption."
    mode = 'CBC'  # or 'CTR'
    ciphertext, hmac, iv = x.encrypt(key, message, iv= bytes.fromhex("AABBCCDDEEFF00112233445566778899"))
    print("Ciphertext:", ciphertext.hex())
    print("HMAC:", hmac.hex())
    decrypted_message = x.decrypt(key, ciphertext, hmac, iv)
    print("Decrypted message:", decrypted_message)