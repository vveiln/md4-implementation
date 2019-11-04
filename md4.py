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

def left_circular_shift(x, s):
    return (((x << s) | (x >> 32 - s)) & WORD_MASK)

def chunk(s, size):
    return [s[i : i + size] for i in range(0, len(s), size)]

class MD4(object):
    NUMBER_OF_ROUNDS = 3
    ROUND_CONSTANT = {0 : 0x00000000, 1 : 0x5a827999, 2 : 0x6ed9eba1}
    ROUND_FUNCTION = {0 : F, 1 : G, 2 : H}
    ROUND_PARAMS = {0 : ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15), (3, 7, 11, 19) * 4),
                    1 : ((0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15), (3, 5, 9, 13) * 4),
                    2 : ((0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15), (3, 9, 11, 15) * 4)}
    
    def __init__(self):
        self.state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        self.message = b''

    def _get_padding(self):
        mlen = len(self.message)
        count = (64 - 1 - 8 - mlen) % 64
        return b'\x80' + count * b'\x00' + struct.pack(b'<Q', 8 * mlen)

    def _pad(self):
        self.message += self._get_padding()

    def update(self, message):
        self.message += bytearray(message, 'utf-8')

    def _round(self, round_number, value, s):
        round_function = self.ROUND_FUNCTION[round_number]
        round_constant = self.ROUND_CONSTANT[round_number]
        self.state[0] = left_circular_shift((self.state[0] 
                                             + round_function(*self.state[1:]) 
                                             + value 
                                             + round_constant) & WORD_MASK, s)
        self._right_circular_shift()
    
    def _right_circular_shift(self, s=1):
        self.state = self.state[-s:] + self.state[:-s]
    
    def _process_block(self, block):
        words = [struct.unpack('<I', w)[0] for w in chunk(block, 4)]
        state = self.state.copy()
        
        for r in range(self.NUMBER_OF_ROUNDS):
            for idx, s in zip(*self.ROUND_PARAMS[r]):
                self._round(r, words[idx], s)
            
        self.state = [(self.state[i] + state[i]) & WORD_MASK for i in range(len(self.state))]

    def digest(self):
        self._pad()
        blocks = chunk(self.message, 64)
        for b in blocks:
            self._process_block(b)
        return struct.pack('<IIII', *self.state)
    
    def hexdigest(self):
        return self.digest().hex()

if __name__ == '__main__':
    md4 = MD4()
    md4.update('a' * 65)
    print(md4.hexdigest())
