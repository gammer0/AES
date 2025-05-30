
from AES_gpt_amend import AES
import random

class CTR_AES:
    def __init__(self, key):
        '''
        生成初始向量， 定义计数器
        
        key: 初始密钥
        '''
        self.AES = AES(key)
        self.iv = None

    def _group(self, data):
        '''
        将数据分组
        
        data: 数据
        return: 分组后的数据
        '''
        data_bytes = data
        data_groups = []
        for i in range(0, len(data_bytes), self.AES.block_size):
            group = bytearray(data_bytes[i:i + self.AES.block_size])
            if len(group) < self.AES.block_size:
                group += bytearray([0] * (self.AES.block_size - len(group)))
            data_groups.append(group)
        return data_groups
    
    def Encrypt(self, plaintext, iv=None):
        
        if iv is None:
            self.iv = bytes([random.randint(0, 255) for _ in range(self.AES.block_size)])
        else:
            self.iv = iv
        self.counter = 0
        if isinstance(plaintext, str):
            plaintext_bytes = bytes(plaintext, 'utf-8')
        else:
            plaintext_bytes = plaintext
        data_groups = self._group(plaintext_bytes)
        ciphertext = []
        for i in range(len(data_groups)):
            counter_block = bytearray(self.iv)
            counter_block[-4:] = self.counter.to_bytes(4, 'big')
            encrypted_counter = self.AES.encrypt_block(counter_block)
            ciphertext.append(
                bytearray([a ^ b for a, b in zip(data_groups[i], encrypted_counter)])
            )
            self.counter += 1
        return b''.join(ciphertext), self.iv

    def Decrypt(self, ciphertext, iv):

        self.iv = iv
        self.counter = 0
        data_groups = self._group(ciphertext)
        plaintext = []
        for i in range(len(data_groups)):
            counter_block = bytearray(self.iv)
            counter_block[-4:] = self.counter.to_bytes(4, 'big')
            encrypted_counter = self.AES.encrypt_block(counter_block)
            plaintext.append(
                bytearray([a ^ b for a, b in zip(data_groups[i], encrypted_counter)])
            )
            self.counter += 1
        return b''.join(plaintext).decode('utf-8')
    
if __name__ == "__main__":
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    cbc_aes = CTR_AES(key)

    plaintext = "This is a test message for CBC mode encryption."
    ciphertext, iv = cbc_aes.Encrypt(plaintext)
    print("Ciphertext:", ciphertext)
    print("IV:", iv)

    decrypted_text = cbc_aes.Decrypt(ciphertext, iv)
    print("Decrypted Text:", decrypted_text)