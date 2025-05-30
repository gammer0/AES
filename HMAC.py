
import random
from SHA256_gpt import SHA_256
from SHAx_discard import bytes_to_bits, bits_to_bytes

class HMAC:
    def __init__(self, safety_parameters):
        self.safety_parameters = safety_parameters

        self.hash =SHA_256()  # Default to SHA-256, can be changed based on safety parameters
        self.block_size = self.hash.block_size
        self.name = f"HMAC-{self.hash.name}"
        self.opad = 0x5c
        self.ipad = 0x36

    def Mac(self, key, message):
        if not isinstance(key, bytes):
            raise TypeError("Key must be of type bytes.")
        if not isinstance(message, bytes):
            raise TypeError("Message must be of type bytes.")


        if len(key) > self.block_size:
            key = bits_to_bytes(self.hash.hash(key))
        
        if len(key) < self.block_size:
            key = key.ljust(self.block_size, b'\x00')

        outer_key = bytes([self.opad ^ b for b in key])
        inner_key = bytes([self.ipad ^ b for b in key])

        inner_hash = self.hash.hash(inner_key + message)
        hmac_result = self.hash.hash(outer_key + inner_hash)

        return hmac_result
    
    def Verify(self, key, message, hmac_value):
        if not isinstance(key, bytes):
            raise TypeError("Key must be of type bytes.")
        if not isinstance(message, bytes):
            raise TypeError("Message must be of type bytes.")
        if not isinstance(hmac_value, bytes):
            raise TypeError("HMAC value must be of type bytes.")

        computed_hmac = self.Mac(key, message)
        return computed_hmac == hmac_value
    
if __name__ == "__main__":
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")
    message = b"Sample message for keylen=blocklen" 

    hmac_instance = HMAC(safety_parameters=256)
    hmac_value = hmac_instance.Mac(key, message)

    print("HMAC Value:", hmac_value.hex()) 

    # Verify the HMAC
    is_valid = hmac_instance.Verify(key, message, hmac_value)
    print("HMAC Verification:", "Valid" if is_valid else "Invalid")