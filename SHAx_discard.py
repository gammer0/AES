
import random
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
def bytes_to_bits(byte_data):
    """将字节流转换为比特流"""
    bit_stream = []
    for byte in byte_data:
        for i in range(8):  # 每个字节8位
            bit = (byte >> (7 - i)) & 0x01  # 从高位到低位提取
            bit_stream.append(str(bit))
    return ''.join(bit_stream)
def bits_to_bytes(bit_stream):
    """将比特流转换为字节流"""
    byte_data = bytearray()
    for i in range(0, len(bit_stream), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bit_stream):
                byte = (byte << 1) | int(bit_stream[i + j])
        byte_data.append(byte)
    return bytes(byte_data)

def right_rotate(value, amount, bits=32):
    """右旋转操作"""
    return ((value >> amount) | (value << (bits - amount))) & ((1 << bits) - 1)

class SHA_256:

    def __init__(self):
        self.name = "SHA-256"
        self.block_size = 64
        self._Hiv =[
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ]



    def _propcess_Message(self, message):
        if not isinstance(message, bytes):
            raise TypeError("Message must be of type bytes.")
        

        def _pad_message(self, message_bits):

            original_length = len(message_bits)
            message_bits += '1'
            while (len(message_bits) + self.block_size) % self.block_size * 8 != 0:
                message_bits += '0'
            message_bits += format(original_length, f'0{self.block_size}b')
            return message_bits
        
        message_bits = bytes_to_bits(message)
        message_bits = _pad_message(self, message_bits)
        message_bits_groups = []
        for i in range(0, len(message_bits), self.block_size * 8):
            group = message_bits[i:i + self.block_size * 8]
            group_bytes = bits_to_bytes(group)
            message_bits_groups.append(group_bytes)
        

        return message_bits_groups
    
    def hash(self, message):
        
        def _message_schedule(message_bytes_group):
            W = []
            for i in range(16):
                W.append(int.from_bytes(message_bytes_group[i*4:(i+1)*4], 'big'))
            for i in range(16, 64):
                s0 = (right_rotate(W[i-15], 7)) ^ (right_rotate(W[i-15], 18)) ^ (W[i-15] >> 3)
                s1 = (right_rotate(W[i-2], 17)) ^ (right_rotate(W[i-2], 9)) ^ (W[i-2] >> 10)
                W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)
            return W
        
        def CH(x, y, z):
            return (x & y) ^ (~x & z)
        
        def MAJ(x, y, z):
            return (x & y) ^ (x & z) ^ (y & z)
        
        def SIGMA0(x):
            return (right_rotate(x, 2)) ^ (right_rotate(x, 13)) ^ (right_rotate(x, 22))
        
        def SIGMA1(x):
            return (right_rotate(x, 6)) ^ (right_rotate(x, 11)) ^ (right_rotate(x, 25))
        
        message_bytes_groups = self._propcess_Message(message)
        H =self._Hiv
        H_prev = []
        for idx, message_bytes_group in enumerate(message_bytes_groups):
            W = _message_schedule(message_bytes_group)
            for i in range(64):
                
                a, b, c, d, e, f, g, h = [H[i] for i in range(8)]

                d2e =(W[i] + K[i] + h + SIGMA1(e) + CH(e, f, g)) & 0xFFFFFFFF
                a2a = d2e + SIGMA0(a) + MAJ(a, b, c) & 0xFFFFFFFF

                b = a
                c = b
                d = c
                e = (d + d2e) & 0xFFFFFFFF
                f = e
                g = f
                h = g
                a = a2a
                H =[a , b, c, d, e, f, g, h]
            if idx == 0:
                H_prev = H
            elif idx > 0:
                for i in range(8):
                    H[i] = (H[i] + H_prev[i]) & 0xFFFFFFFF
                H_prev = H
        
        hash_value = b''.join(h.to_bytes(4, 'big') for h in H)
        return bytes_to_bits(hash_value)
        


class SHA_224(SHA_256):
    def __init__(self):
        super().__init__()
        self.name = "SHA-224"
        self.block_size = 64
    
    def hash(self, message):
        # SHA-224 specific implementation
        hash_val =super().hash(message)
        return hash_val[:224]


class SHA_512:
    def __init__(self):
        self.name = "SHA-512"
        self.block_size = 128
        self._Hiv = self._set_Hiv()

    def _set_Hiv(self):
        Hiv =[random.randint(0, 255) for _ in range(8)]
        return Hiv


    def _propcess_Message(self, message):
        if not isinstance(message, bytes):
            raise TypeError("Message must be of type bytes.")
        

        def _pad_message(self, message_bits):

            original_length = len(message_bits)
            message_bits += '1'
            while (len(message_bits) + self.block_size) % self.block_size * 8 != 0:
                message_bits += '0'
            message_bits += format(original_length, f'0{self.block_size}b')
            return message_bits
        
        message_bits = bytes_to_bits(message)
        message_bits = _pad_message(self, message_bits)
        message_bits_groups = []
        for i in range(0, len(message_bits), self.block_size * 8):
            group = message_bits[i:i + self.block_size * 8]
            group_bytes = bits_to_bytes(group)
            message_bits_groups.append(group_bytes)
        

        return message_bits_groups
    
    def hash(self, message):
        
        def _message_schedule(message_bytes_group):
            W = []
            for i in range(16):
                W.append(int.from_bytes(message_bytes_group[i*8:(i+1)*8], 'big'))
            for i in range(16, 64):
                s0 = (right_rotate(W[i-15], 1, 64)) ^ (right_rotate(W[i-15], 8, 64)) ^ (W[i-15] >> 7)
                s1 = (right_rotate(W[i-2], 19, 64)) ^ (right_rotate(W[i-2], 61, 64)) ^ (W[i-2] >> 6)
                W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFFFFFFFFFF)
            return W
        
        def CH(x, y, z):
            return (x & y) ^ (~x & z)
        
        def MAJ(x, y, z):
            return (x & y) ^ (x & z) ^ (y & z)
        
        def SIGMA0(x):
            return (right_rotate(x, 28, 64)) ^ (right_rotate(x, 34, 64)) ^ (right_rotate(x,39, 64))
        
        def SIGMA1(x):
            return (right_rotate(x, 14, 64)) ^ (right_rotate(x, 18, 64)) ^ (right_rotate(x, 41, 64))
        
        message_bytes_groups = self._propcess_Message(message)

        H =self._Hiv
        H_prev = []
        for idx, message_bytes_group in enumerate(message_bytes_groups):
            for i in range(64):
                W = _message_schedule(message_bytes_group)
                a, b, c, d, e, f, g, h = [H[i] for i in range(8)]

                d2e =(W[i] + K[i] + h + SIGMA1(e) + CH(e, f, g)) & 0xFFFFFFFFFFFFFFFF
                a2a = d2e + SIGMA0(a) + MAJ(a, b, c) & 0xFFFFFFFFFFFFFFFF

                b = a
                c = b
                d = c
                e = (d + d2e) & 0xFFFFFFFFFFFFFFFF
                f = e
                g = f
                h = g
                a = a2a
                H =a , b, c, d, e, f, g, h
            if idx == 0:
                H_prev = H
            elif idx > 0:
                for i in range(8):
                    H[i] = (H[i] + H_prev[i]) & 0xFFFFFFFFFFFFFFFF
                H_prev = H
        
        hash_value = b''.join(h.to_bytes(8, 'big') for h in H)
        return bytes_to_bits(hash_value)


class SHA_384(SHA_512):
    def __init__(self):
        super().__init__()
        self.name = "SHA-384"
        self.block_size = 128
    
    def hash(self, message_groups):
        # SHA-224 specific implementation
        hash_val =super().hash(message_groups)
        return hash_val[:384]
    
def bits_to_hex(bit_stream):
    """将比特流转换为十六进制字符串"""
    byte_data = bits_to_bytes(bit_stream)
    return byte_data.hex().upper()

if __name__ == "__main__":
    sha256 = SHA_256()
    message = b"abc"
    hash_value = sha256.hash(message)
    print(f"SHA-256 Hash: {bits_to_hex(hash_value)}")
