#!/usr/bin/python

# Parse primitives
from libparse.bindata import BinData
from libparse.bytestream import ByteStream
from libparse.entry import Entry
from libparse.entry import EntryList

# LEB128 Structures ---------------
from dex_leb128 import ULEB128
from dex_leb128 import ULEB128P1
from dex_leb128 import SLEB128

# Dex Encoded Structures -------------

#This is a hack
class EncodedValue(Entry):
    def __init__(self,bstream,offset=None):
        self.corrupted = False

        self._prepare_stream(bstream,offset)

        self.value_properties = BinData(1)
        self.value_properties.init_data(bstream.read(1))

        prop = self.value_properties.data[0]

        self.value_arg = prop >> 5 + 1
        self.value_type = prop & 0x1f

        if self.value_type == 0x1c:
            self.value = EncodedArray(bstream)
        elif self.value_type == 0x1d:
            self.value = EncodedAnnotation(bstream)
        elif self.value_type == 0x1f:
            self.value = (self.value_arg == 0)
        elif self.value_type in [0x00,0x02,0x03,0x04,0x06,0x10,
                                 0x11,0x17,0x18,0x19,0x1a,0x1b]:
            self.value = BinData(self.value_arg+1)
            self.value.init_data(bstream.read(self.value_arg+1))

    def blob(self):
        raise("Implement me!")

AnnotationElement = Entry.create('AnnotationElement',[
        ['name_idx', 1, ULEB128],
        ['value',    1, EncodedValue],
])

EncodedAnnotation = Entry.create('EncodedAnnotation',[
        ['type_idx',      1, ULEB128],
        ['size',          1, ULEB128],
        ['elements', 'size', EntryList, AnnotationElement],
])

EncodedArray = Entry.create('EncodedArray',[
        ['size',          1, ULEB128],
        ['values', 'size', EntryList, EncodedValue],
])
