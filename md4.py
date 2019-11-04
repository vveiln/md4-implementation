import struct
WORD_MASK = (1 << 32) - 1
BYTES_IN_WORD = 4
BITS_IN_BYTE = 8
BITS_IN_WORD = BITS_IN_BYTE * BYTES_IN_WORD

def left_circular_shift(x, s):
    return (((x << s) | (x >> BITS_IN_WORD - s)) & WORD_MASK)

def chunk(s, size):
    return [s[i : i + size] for i in range(0, len(s), size)]

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


class MD4(object):
    NUMBER_OF_ROUNDS = 3
    BLOCK_SIZE = 64
    ROUND_CONSTANT = {0 : 0x00000000, 1 : 0x5a827999, 2 : 0x6ed9eba1}
    ROUND_FUNCTION = {0 : F, 1 : G, 2 : H}
    ROUND_PARAMS = {0 : ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15), (3, 7, 11, 19) * 4),
                    1 : ((0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15), (3, 5, 9, 13) * 4),
                    2 : ((0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15), (3, 9, 11, 15) * 4)}

    def __init__(self):
        self.state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        self.message = b''

    def update(self, message):
        self.message += bytearray(message, 'utf-8') if isinstance(message, str) else message

    def digest(self):
        self._pad()
        self._process_blocks()
        return struct.pack('<IIII', *self.state)

    def hexdigest(self):
        return self.digest().hex()

    def _get_padding(self):
        message_len = len(self.message)
        count = (self.BLOCK_SIZE
                 - 1
                 - 8
                 - message_len) % self.BLOCK_SIZE
        return b'\x80' + count * b'\x00' + struct.pack(b'<Q', BITS_IN_BYTE * message_len)

    def _pad(self):
        self.message += self._get_padding()

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

    def _process_blocks(self):
        blocks = chunk(self.message, self.BLOCK_SIZE)
        for b in blocks:
            self._process_block(b)

    def _process_block(self, block):
        word_from_str = lambda s: struct.unpack('<I', s)[0]
        words = [word_from_str(s) for s in chunk(block, BYTES_IN_WORD)]
        state = self.state.copy()

        for r in range(self.NUMBER_OF_ROUNDS):
            for idx, shift in zip(*self.ROUND_PARAMS[r]):
                self._round(r, words[idx], shift)

        self.state = [(i + j) & WORD_MASK for i, j in zip(self.state, state)]


if __name__ == '__main__':
    md4 = MD4()
    md4.update('message you want to compress')
    print(md4.hexdigest())
