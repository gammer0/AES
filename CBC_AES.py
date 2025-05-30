
from AES_gpt_amend import AES
import random

class CBC_AES:
    def __init__(self, key):
        '''
        生成初始向量
        
        AES: aes算法
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
        '''
        CBC模式加密
        
        plaintext: 明文
        return: 密文
        '''
        if iv is None:
            self.iv = bytes([random.randint(0, 255) for _ in range(self.AES.block_size)])
        else:
            self.iv = iv
        if isinstance(plaintext, str):
            plaintext_bytes = bytes(plaintext, 'utf-8')
        else:
            plaintext_bytes = plaintext
        data_groups = self._group(plaintext_bytes)
        ciphertext = [self.iv]

        for i in range(0, len(data_groups)):
            ciphertext.append(
                self.AES.encrypt_block(
                    bytearray([a ^ b for a, b in zip(data_groups[i], ciphertext[i])])
                )
            )

        return b''.join([bytes(group) for group in ciphertext[1:]]), self.iv

    def Decrypt(self, ciphertext, iv):
        '''
        CBC模式解密
        
        ciphertext: 密文
        return: 明文
        '''
        self.iv = iv
        data_groups = self._group(ciphertext)
        plaintext = []
        
        decrypted_block = self.AES.decrypt_block(data_groups[0])
        plaintext.append(
            bytearray([a ^ b for a, b in zip(decrypted_block, self.iv)])
        )

        for i in range(1, len(data_groups)):
            decrypted_block = self.AES.decrypt_block(data_groups[i])
            plaintext.append(
                bytearray([a ^ b for a, b in zip(decrypted_block, data_groups[i-1])])
            )
        return b''.join(plaintext).decode('utf-8')
    

if __name__ == "__main__":
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    cbc_aes = CBC_AES(key)

    plaintext = "This is a test message for CBC mode encryption."
    ciphertext, iv = cbc_aes.Encrypt(plaintext)
    print("Ciphertext:", ciphertext)
    print("IV:", iv)

    decrypted_text = cbc_aes.Decrypt(ciphertext, iv)
    print("Decrypted Text:", decrypted_text)