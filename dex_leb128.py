#!/usr/bin/python

from libparse.bindata import BinData
from libparse.entry import Entry

def len_leb128(self,bstream):
    """
    Find the length of a leb128 field in a bytestream
    """
    start = bstream.offset

    length = 0

    r_byte = bstream.read(1)

    if r_byte != 0x0:
        length = 1

        while len(r_byte) == 1 and length < 5 and r_byte[0] & 0x80 != 0x0:
            length+=1
            r_byte = bstream.read(1)

    bstream.offset = start

    return length

def uleb128_to_int(self):
    value = 0
    for b in reversed(self.value.data):
        value = value * 128 + (b & 0x7F)
    return value

def uleb128p1_to_int(self):
    value = 0
    for b in reversed(self.value.data):
        value = value * 128 + (b & 0x7F)
    return value-1

def sleb128_to_int(self):
    value = 0
    for b in reversed(self.value.data):
        value = value * 128 + (b & 0x7F)
    if self.value.data[-1] & 0x40 != 0:
        value = value | ~((1 << (len(self.value.data)*7))-1)
    return value

# LEB128 Structures

ULEB128 = Entry.create('ULEB128',[['value', len_leb128, BinData],])
ULEB128.__int__ = uleb128_to_int

ULEB128P1 = Entry.create('ULEB128P1',[['value', len_leb128, BinData],])
ULEB128P1.__int__ = uleb128p1_to_int

SLEB128 = Entry.create('SLEB128',[['value', len_leb128, BinData],])
SLEB128.__int__ = sleb128_to_int
