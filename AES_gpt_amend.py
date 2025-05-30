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
        self._generate_sbox_tables()
        self.round_keys = self._key_expansion(key, len(key) * 8)

    def _generate_sbox_tables(self):
        self.sbox = [0] * 256
        self.inv_sbox = [0] * 256
        for i in range(256):
            if i == 0:
                b = 0
            else:
                b = int(GF256(i) ** -1)
            c = b ^ (b << 1) ^ (b << 2) ^ (b << 3) ^ (b << 4) ^ 0x63
            s = c & 0xFF
            self.sbox[i] = s
            self.inv_sbox[s] = i

    def _key_expansion(self, key_bytes, key_size_in_bits):
        Nk = key_size_in_bits // 32
        if Nk == 4:
            Nr = 10
        elif Nk == 6:
            Nr = 12
        elif Nk == 8:
            Nr = 14
        Nb = 4
        w = [[0] * 4 for _ in range(Nb * (Nr + 1))]
        for i in range(Nk):
            w[i] = list(key_bytes[4 * i: 4 * (i + 1)])
        for i in range(Nk, Nb * (Nr + 1)):
            temp = list(w[i - 1])
            if i % Nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [self.sbox[b] for b in temp]
                temp[0] ^= Rcon[i // Nk - 1]
            elif Nk > 6 and i % Nk == 4:
                temp = [self.sbox[b] for b in temp]
            w[i] = [w[i - Nk][j] ^ temp[j] for j in range(4)]
        round_keys_matrices = []
        for round_num in range(Nr + 1):
            round_key_matrix = [[0] * 4 for _ in range(4)]
            for c in range(4):
                word = w[round_num * Nb + c]
                for r in range(4):
                    round_key_matrix[r][c] = word[r]
            round_keys_matrices.append(round_key_matrix)
        return round_keys_matrices

    def encrypt_block(self, block):
        def array2matrix(block):
            return [list(block[i::4]) for i in range(4)]

        def matrix2array(matrix):
            return [matrix[j][i] for i in range(4) for j in range(4)]

        def add_round_key(state, key):
            return [[state[i][j] ^ key[i][j] for j in range(4)] for i in range(4)]

        def sub_bytes(state):
            return [[self.sbox[state[i][j]] for j in range(4)] for i in range(4)]

        def shift_rows(state):
            return [state[i][i:] + state[i][:i] for i in range(4)]

        def mix_columns(state):
            const = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
            result = [[0] * 4 for _ in range(4)]
            for i in range(4):
                for j in range(4):
                    val = GF256(0)
                    for k in range(4):
                        val += GF256(const[i][k]) * GF256(state[k][j])
                    result[i][j] = int(val)
            return result

        state = array2matrix(block)
        state = add_round_key(state, self.round_keys[0])
        for r in range(1, len(self.round_keys) - 1):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, self.round_keys[r])
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, self.round_keys[-1])
        return matrix2array(state)

    def decrypt_block(self, block):
        def array2matrix(block):
            return [list(block[i::4]) for i in range(4)]

        def matrix2array(matrix):
            return [matrix[j][i] for i in range(4) for j in range(4)]

        def add_round_key(state, key):
            return [[state[i][j] ^ key[i][j] for j in range(4)] for i in range(4)]

        def inv_sub_bytes(state):
            return [[self.inv_sbox[state[i][j]] for j in range(4)] for i in range(4)]

        def inv_shift_rows(state):
            return [state[i][-i:] + state[i][:-i] for i in range(4)]

        def inv_mix_columns(state):
            const = [[0x0e, 0x0b, 0x0d, 0x09],
                     [0x09, 0x0e, 0x0b, 0x0d],
                     [0x0d, 0x09, 0x0e, 0x0b],
                     [0x0b, 0x0d, 0x09, 0x0e]]
            result = [[0] * 4 for _ in range(4)]
            for i in range(4):
                for j in range(4):
                    val = GF256(0)
                    for k in range(4):
                        val += GF256(const[i][k]) * GF256(state[k][j])
                    result[i][j] = int(val)
            return result

        state = array2matrix(block)
        state = add_round_key(state, self.round_keys[-1])
        for r in range(len(self.round_keys) - 2, 0, -1):
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state)
            state = add_round_key(state, self.round_keys[r])
            state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, self.round_keys[0])
        return matrix2array(state)


if __name__ == "__main__":
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    aes = AES(key)

    plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    ciphertext = aes.encrypt_block(plaintext)
    print("Ciphertext:", bytes(ciphertext).hex())

    decrypted = aes.decrypt_block(ciphertext)
    print("Decrypted :", bytes(decrypted).hex())

    assert bytes(decrypted) == plaintext, "Decryption failed!"
