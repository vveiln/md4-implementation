import struct
import pytest
from md4 import *
from Crypto.Hash import MD4 as ExpectedMD4
from os import urandom

class TestPadding(object):
    def test_boundary_padding(self):
        message_len = 56
        md4 = MD4()
        md4.update('a' * message_len)
        assert md4._get_padding() == b'\x80' + 63 * b'\x00' + struct.pack('<Q', message_len * 8)

    def test_min_padding(self):
        message_len = 0
        md4 = MD4()
        md4.update('a' * message_len)
        assert md4._get_padding() == b'\x80' + 55 * b'\x00' + struct.pack('<Q', message_len * 8)

    def test_max_padding(self):
        message_len = 63
        md4 = MD4()
        md4.update('a' * message_len)
        assert md4._get_padding() == b'\x80' + 56 * b'\x00' + struct.pack('<Q', message_len * 8)

class TestMul(object):
    def test(self):
        assert mul(0b101010, 0b1101) == 0b1000

    def test_boundary(self):
        assert mul((1 << 33) - 1, 0b1101) == 0b1101

    def test_zero(self):
        assert mul(0b101010, 0b010101) == 0b0

class TestNeg(object):
    def test(self):
        assert neg(0b101010) == ((1 << 32) - 1) ^ 0b101010

    def test_zero_boundary(self):
        assert neg((1 << 33) - 1) == 0b0

    def test_boundary(self):
        assert neg(((1 << 33) - 1) ^ ((1 << 10) - 1)) == ((1 << 10) - 1)

class TestF(object):
    def test(self):
        x = 0b101010
        y = 0b001010
        z = 0b001101
        assert F(x, y, z) == 0b001111

    def test_true(self):
        x = 0b111111
        y = 0b001010
        z = 0b001101
        assert F(x, y, z) == y

    def test_false(self):
        x = 0b0
        y = 0b001010
        z = 0b001101
        assert F(x, y, z) == z

    def test_boundaries(self):
        x = (1 << 36) - 1
        y = (1 << 35) - 1
        z = 0b1
        assert F(x, y, z) == (1 << 32) - 1

class TestG(object):
    def test(self):
        x = 0b101010
        y = 0b001010
        z = 0b001101
        assert G(x, y, z) == 0b001010

    def test_true(self):
        x = 0b111111
        y = 0b111111
        z = 0b001101
        assert G(x, y, z) == y

    def test_false(self):
        x = 0b0
        y = 0b0
        z = 0b001101
        assert G(x, y, z) == 0b0

    def test_boundaries(self):
        x = (1 << 36) - 1
        y = (1 << 35) - 1
        z = 0b1
        assert F(x, y, z) == (1 << 32) - 1

class TestH(object):
    def test(self):
        x = 0b101010
        y = 0b001010
        z = 0b001101
        assert H(x, y, z) == 0b101101

    def test_true(self):
        x = 0b111111
        y = 0b111111
        z = 0b001101
        assert H(x, y, z) == z

    def test_boundaries(self):
        x = (1 << 36) - 1
        y = (1 << 35) - 1
        z = 0b1
        assert H(x, y, z) == 0b1

class TestLrot(object):
    def test(self):
        x = 0b10
        assert left_circular_shift(x, 1) == 0b100

    def test_cycling(self):
        x = 0b1
        assert left_circular_shift(x, 32) == 0b1

    def test_max(self):
        x = 0b10101010101010101111111111111111
        assert left_circular_shift(x, 16) == 0b11111111111111111010101010101010

class TestMD4(object):
    def test(self):
        m = 'abcd'
        expected = ExpectedMD4.new()
        expected.update(m)

        actual = MD4()
        actual.update(m)
        assert actual.hexdigest() == expected.hexdigest()

    def test_two_blocks(self):
        m = 'a' * 65
        expected = ExpectedMD4.new()
        expected.update(m)

        actual = MD4()
        actual.update(m)
        assert actual.hexdigest() == expected.hexdigest()

    def test_max_block(self):
        m = 'a' * 64
        expected = ExpectedMD4.new()
        expected.update(m)

        actual = MD4()
        actual.update(m)
        assert actual.hexdigest() == expected.hexdigest()

    def test_many_blocks(self):
        m = 'a' * (64 * 53)
        expected = ExpectedMD4.new()
        expected.update(m)

        actual = MD4()
        actual.update(m)
        assert actual.hexdigest() == expected.hexdigest()

    def test_unicode(self):
        m = 'юникод тест'
        expected = ExpectedMD4.new()
        expected.update(m)

        actual = MD4()
        actual.update(m)
        assert actual.hexdigest() == expected.hexdigest()

