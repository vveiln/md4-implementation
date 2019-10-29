import struct
WORD_MASK = (1 << 32) - 1

def mul(x, y):
    return (x & y) & WORD_MASK

def neg(x):
    return (x ^ WORD_MASK) & WORD_MASK

def F(x, y, z):
    '''acts as a conditional if X then Y else Z'''
    return mul(x, y) | mul(neg(x), z)        

def G(x, y, z):
    '''acts as a majority function'''
    return mul(x, y) | mul(x, z) | mul(y, z)

def H(x, y, z):
    return (x ^ y ^ z) & WORD_MASK

def r1(state, c, s):
    return lrot((state[0] + F(state[1], state[2], state[3]) + c) & WORD_MASK, s)

def r2(state, c, s):
    return lrot((state[0] + G(state[1], state[2], state[3]) + c + 0x5a827999) & WORD_MASK, s)

def r2(state, c, s):
    return lrot((state[0] + H(state[1], state[2], state[3]) + c + 0x6ed9eba1) & WORD_MASK, s)

def lrot(x, s):
    return (((x << s) | (x >> 32 - s)) & WORD_MASK)

def list_rrot(l, s=1):
    return l[s:] + l[:s]

def chunk(s, size):
    return [s[i : i + size] for i in range(0, len(s), size)]

class MD4(object):
    def __init__(self):
        self.A = 0x01234567
        self.B = 0x89abcdef
        self.C = 0xfedcba98
        self.D = 0x76543210
        self.chunks = None
        self.message = b''

    def get_padding(self, message_length):
        count = (64 - 1 - 8 - message_length) % 64
        return b'\x80' + count * b'\x00' + struct.pack('>Q', 8 * message_length)

    def pad(self):
        self.message += self.get_padding(len(self.message) % 64)

    def update(self, message):
        self.message += bytearray(message, 'utf-8')

    def _process_block(self, idx):
        X = list(map(lambda x: struct.unpack('>I', x)[0], chunk(self.chunks[idx], 4)))
        state = [self.A, self.B, self.C, self.D]

        for i, j in zip(range(16), [3, 7, 11, 19] * 4):        
            state[0] = r1(state, X[i], j)
            state = list_rrot(state)
        
        for i, j in zip([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 4, 3, 7, 11, 15], [3, 5, 9, 13] * 4):
            state[0] = r2(state, X[i], j)
            state = list_rrot(state)

        for i, j in zip():
            state[0] = r2(state, X[i], j)
            self = list_rrot(state)

        self.A = self.A + state[0]
        self.B = self.B + state[1]
        self.C = self.C + state[2]
        self.D = self.D + state[3]


    def digest(self):
        self.pad()
        self.chunks = chunk(self.message, 64)
        for c in range(len(self.chunks)):
            self._process_block(c)
        return hex(self.D)[2:] + hex(self.C)[2:] +hex(self.B)[2:] + hex(self.A)[2:]
        

if __name__ == "__main__":
    md4 = MD4()
    md4.update('aaaa')
    print(md4.digest())
