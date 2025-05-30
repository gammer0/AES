

import galois
GF256 = galois.GF(2**8, irreducible_poly=0x11b)
Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
class AES:
    
    def __init__(self, key):

        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long.")
        self.key = key
        self.name = f"AES-{len(key) * 8}"
        self.block_size = 16  
        self.round_keys = self._key_expansion(key, len(key) * 8)
        

    '''通过伽罗瓦域逆元和仿射变换，生成0-255的S盒与逆S盒查找表，
    错误：直接过算法计算S盒输出，导致结果值超出伽罗瓦域，进而导致截断无法与逆S盒结果对应'''

    def Sbox(self, a):
        b = GF256(a) ** -1
        b = int(b)
        c = b ^ (b << 1) ^ (b << 2) ^ (b << 3) ^ (b << 4) ^ 0x63
        return c & 0xFF
    
    def Sbox_(self, c):
        b = (c << 1) ^ (c << 3) ^ (c << 6) ^ 0x05
        b = b & 0xFF
        a = GF256(b) ** -1
        a = int(a)
        return a & 0xFF
    
    
    def _key_expansion(self, key_bytes, key_size_in_bits):
        Nk = key_size_in_bits // 32
        if Nk == 4: Nr = 10
        elif Nk == 6: Nr = 12
        elif Nk == 8: Nr = 14
        Nb = 4
        w = [[0]*4 for _ in range(Nb * (Nr + 1))]
        for i in range(Nk):
            w[i] = list(key_bytes[4*i : 4*(i+1)])
        for i in range(Nk, Nb * (Nr + 1)):
            temp = list(w[i-1])
            if i % Nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [self.Sbox(b) for b in temp]
                temp[0] = temp[0] ^ Rcon[i // Nk -1]
            elif Nk > 6 and i % Nk == 4:
                temp = [self.Sbox(b) for b in temp]
            w[i] = [w[i-Nk][j] ^ temp[j] for j in range(4)]
        round_keys_matrices = []
        for round_num in range(Nr + 1):
            round_key_matrix = [[0]*4 for _ in range(4)]
        for c in range(4):
            word_from_w = w[round_num * Nb + c]
            for r in range(4):
                round_key_matrix[r][c] = word_from_w[r]
        round_keys_matrices.append(round_key_matrix)
        return round_keys_matrices

    def encrypt_block(self, block):
        
        '''可通过python跳跃索引切片直接构建以列为单位的矩阵'''
        def array2matrix44(block):
            matrix =[[block[i + j * 4] for j in range(4)] for i in range(4)]
            matrix_transpose = [[matrix[j][i] for j in range(4)] for i in range(4)]
            return matrix_transpose
        
        def matrix2array(matrix):
            return [matrix[j][i] for j in range(4) for i in range(4)]

        '''封装程度不够'''
        def _add_round_key(state, round_key, idx):
            return [[state[i][j] ^ round_key[idx][i][j] for j in range(4)] for i in range(4)]

        def _sub_bytes(state):
            return [[self.Sbox(state[i][j]) for j in range(4)] for i in range(4)]

        '''行移位操作，循环左移'''
        '''可优化参数'''
        def _shift_rows(state):
            
            def Cycle_shift(row, count):
                return row[count % len(row):] + row[:count % len(row)]
            for i in range(4):
                state[i] =Cycle_shift(state[i], i)
            
            return state

        '''列混合计算使用伽罗瓦域，计算结果存储为int类型，需截断为0-255的范围'''
        def _mix_columns(state):    
            const_matrix =[ [0x02, 0x03, 0x01, 0x01], 
                            [0x01, 0x02, 0x03, 0x01],
                            [0x01, 0x01, 0x02, 0x03],
                            [0x03, 0x01, 0x01, 0x02]]
            
            result_state =[[0,0,0,0] * 4]
            for i in range(4):
                for j in range(4):
                    for k in range(4):
                        result_state[i][j] =GF256(result_state[i][j])
                        result_state[i][j] +=GF256(const_matrix[i][k]) * GF256(state[k][j])
                        result_state[i][j] &= 0xFF
            
            return result_state
        
        block = array2matrix44(block)
        block =_add_round_key(block, self.round_keys, 0)


        for round_num in range(1, len(self.round_keys)-1):
            block = _sub_bytes(block)
            block = _shift_rows(block)
            block = _mix_columns(block)
            block = _add_round_key(block, self.round_keys, round_num)
        
        block = _sub_bytes(block)
        block = _shift_rows(block)
        block = _add_round_key(block, self.round_keys, len(self.round_keys) - 1)
                    
        block = matrix2array(block)
        return block


    def decrypt_block(self, block):

        def array2matrix44(block):
            matrix =[[block[i + j * 4] for j in range(4)] for i in range(4)]
            matrix_transpose = [[matrix[j][i] for j in range(4)] for i in range(4)]
            return matrix_transpose
        
        def matrix2array(matrix):
            return [matrix[j][i] for j in range(4) for i in range(4)]

        def _add_round_key(state, round_key, idx):
            return [[state[i][j] ^ round_key[idx][i][j] for j in range(4)] for i in range(4)]

        def _sub_bytes(state):
            return [[self.Sbox_(state[i][j]) for j in range(4)] for i in range(4)]

        def _shift_rows(state):
            
            def Cycle_shift(row, count):
                return row[-count % len(row):] + row[:-count % len(row)]
            for i in range(4):
                state[i] =Cycle_shift(state[i], i)
            
            return state


        def _mix_columns(state):    
            inv_const_matrix = [
            [0x0e, 0x0b, 0x0d, 0x09],
            [0x09, 0x0e, 0x0b, 0x0d],
            [0x0d, 0x09, 0x0e, 0x0b],
            [0x0b, 0x0d, 0x09, 0x0e]
            ]
            
            result_state =[[0,0,0,0] * 4]
            for i in range(4):
                for j in range(4):
                    for k in range(4):
                        result_state[i][j] =GF256(result_state[i][j])
                        result_state[i][j] +=GF256(inv_const_matrix[i][k]) * GF256(state[k][j])
                        result_state[i][j] &= 0xFF
            
            return result_state
        
        block = array2matrix44(block)
        block = _add_round_key(block, self.round_keys, len(self.round_keys) - 1)
        for round_num in range(len(self.round_keys) - 2, 1, -1):
            block = _shift_rows(block)
            block = _sub_bytes(block)
            block = _add_round_key(block, self.round_keys, round_num)
            block = _mix_columns(block)
        
        block = _shift_rows(block)
        block = _sub_bytes(block)
        block = _add_round_key(block, self.round_keys, 0)

        block = matrix2array(block)
        return block
    

if __name__ == "__main__":
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    aes = AES(key)
    
    plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    ciphertext = aes.encrypt_block(plaintext)
    print("Ciphertext:", ciphertext)

    decrypted_text = aes.decrypt_block(ciphertext)
    print("Decrypted text:", decrypted_text)
    
    assert decrypted_text == plaintext, "Decryption failed!"