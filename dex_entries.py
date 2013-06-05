#!/usr/bin/python

# Parse primitives
from libparse.bindata import BinData
from libparse.bindata import BinInt
from libparse.bindata import BinHex
from libparse.bindata import BinStr

from dex_bin import BinMapType

from libparse.bytestream import ByteStream
from libparse.entry import Entry
from libparse.entry import EntryList

# LEB128 Structures ---------------
from dex_leb128 import ULEB128
from dex_leb128 import ULEB128P1
from dex_leb128 import SLEB128

# Dex Encoded Structures -------------
from dex_encoded import EncodedAnnotation
from dex_encoded import EncodedArray

# DEX Structures -----------------

Header = Entry.create('Header',[
        ['magic',           8, BinData],
        ['checksum',        4, BinHex],
        ['signature',      20, BinData],
        ['file_size',       4, BinInt],
        ['header_size',     4, BinInt],
        ['endian_tag',      4, BinHex],
        ['link_size',       4, BinInt],
        ['link_off',        4, BinHex],
        ['map_off',         4, BinHex],
        ['string_ids_size', 4, BinInt],
        ['string_ids_off',  4, BinHex],
        ['type_ids_size',   4, BinInt],
        ['type_ids_off',    4, BinHex],
        ['proto_ids_size',  4, BinInt],
        ['proto_ids_off',   4, BinHex],
        ['field_ids_size',  4, BinInt],
        ['field_ids_off',   4, BinHex],
        ['method_ids_size', 4, BinInt],
        ['method_ids_off',  4, BinHex],
        ['class_defs_size', 4, BinInt],
        ['class_defs_off',  4, BinHex],
        ['data_size',       4, BinInt],
        ['data_off',        4, BinHex],
        ])

MapItem = Entry.create('MapItem',[
        ['type',   2, BinMapType],
        ['unused', 2, BinHex],
        ['size',   4, BinInt],
        ['offset', 4, BinHex],
])

MapList = Entry.create('MapList',[
        ['size',     4, BinInt],
        ['list','size', EntryList, MapItem],
])

StringId = Entry.create('StringId',[
        ['string_data_off', 4, BinHex],
])

def len_str(self,bstream):
    """
    Find the length of a null terminated string in a bytestream
    """
    start = bstream.offset
    length = 1 #add the \0 to the data read

    r_byte = bstream.read(1)
    while len(r_byte) == 1 and r_byte[0] != 0x0:
        length+=1
        r_byte = bstream.read(1)

    bstream.offset = start

    return length

StringData = Entry.create('StringData',[
        ['utf16_size',       1, ULEB128],
        ['data',       len_str, BinStr],
])

TypeId = Entry.create('TypeId',[
        ['descriptor_idx', 4, BinInt],
])

ProtoId = Entry.create('ProtoId',[
        ['shorty_idx',      4, BinInt],
        ['return_type_idx', 4, BinInt],
        ['parameters_off',  4, BinHex],
])

FieldId = Entry.create('FieldId',[
        ['class_idx', 2, BinInt],
        ['type_idx',  2, BinInt],
        ['name_idx',  4, BinInt],
])

MethodId = Entry.create('MethodId',[
        ['class_idx', 2, BinInt],
        ['proto_idx', 2, BinInt],
        ['name_idx',  4, BinInt],
])

ClassDef = Entry.create('ClassDef',[
        ['class_idx',         4, BinInt],
        ['access_flags',      4, BinHex],
        ['superclass_idx',    4, BinInt],
        ['interfaces_off',    4, BinHex],
        ['source_file_idx',   4, BinInt],
        ['annotations_off',   4, BinHex],
        ['class_data_off',    4, BinHex],
        ['static_values_off', 4, BinHex],
])

EncodedField = Entry.create('EncodedField',[
        ['field_idx_diff', 1, ULEB128],
        ['access_flags',   1, ULEB128],
])

EncodedMethod = Entry.create('EncodedMethod',[
        ['method_idx_diff', 1, ULEB128],
        ['access_flags',    1, ULEB128],
        ['code_off',        1, ULEB128],
])

ClassData = Entry.create('ClassData',[
        ['static_fields_size',   1, ULEB128],
        ['instance_fields_size', 1, ULEB128],
        ['direct_methods_size',  1, ULEB128],
        ['virtual_methods_size', 1, ULEB128],
        ['static_fields',   'static_fields_size',   EntryList, EncodedField],
        ['instance_fields', 'instance_fields_size', EntryList, EncodedField],
        ['direct_methods',  'direct_methods_size',  EntryList, EncodedMethod],
        ['virtual_methods', 'virtual_methods_size', EntryList, EncodedMethod],
])

TypeItem = Entry.create('TypeItem',[
        ['type_idx', 2, BinInt],
])

TypeList = Entry.create('TypeList',[
        ['size',      4, BinInt],
        ['list', 'size', EntryList, TypeItem],
])

EncodedTypeAddrPair = Entry.create('EncodedTypeAddrPair',[
        ['type_idx', 1, ULEB128],
        ['addr',     1, ULEB128],
])

def ech_handlers_size(self,bstream):
    return abs(int(self.size))

def ech_catch_size(self,bstream):
    if int(self.size) < 0:
        return 1
    else:
        return 0

EncodedCatchHandler = Entry.create('EncodedCatchHandler',[
        ['size', 1, SLEB128],
        ['handlers', ech_handlers_size, EntryList, EncodedTypeAddrPair],
        ['catch_all_addr', ech_catch_size , ULEB128],
])

EncodedCatchHandlerList = Entry.create('EncodedCatchHandlerList',[
        ['size', 1, ULEB128],
        ['list', 'size', EntryList, EncodedCatchHandler],
])

TryItem = Entry.create('TryItem',[
        ['start_addr',  4, BinHex],
        ['insn_count',  2, BinInt],
        ['handler_off', 2, BinHex],
])

def ci_insns_size(self,bstream):
    return int(self.insns_size)*2

def ci_padding_size(self,bstream):
    if (int(self.tries_size) > 0 and
        int(self.insns_size) % 2 != 0):
        return 2
    else:
        return 0

CodeItem = Entry.create('CodeItem',[
        ['registers_size', 2, BinInt],
        ['ins_size',       2, BinInt],
        ['outs_size',      2, BinInt],
        ['tries_size',     2, BinInt],
        ['debug_info_off', 4, BinHex],
        ['insns_size',     2, BinInt],
        ['insns',    ci_insns_size, BinData],
        ['padding',  ci_padding_size, BinHex],
        ['tries',    'tries_size', EntryList, TryItem],
        ['handlers', 'tries_size', EncodedCatchHandlerList, None],
])

DebugInfoItem = Entry.create('DebugInfoItem',[
        ['line_start', 1, ULEB128],
        ['parameters_size', 1, ULEB128],
        ['parameter_names', 'parameters_size', EntryList, ULEB128P1],
])

FieldAnnotation = Entry.create('FieldAnnotation',[
        ['field_idx',4,BinInt],
        ['annotations_off',4,BinHex],
])

MethodAnnotation = Entry.create('MethodAnnotation',[
        ['method_idx',4,BinInt],
        ['annotations_off',4,BinHex],
])

ParameterAnnotation = Entry.create('ParameterAnnotation',[
        ['method_idx',4,BinInt],
        ['annotations_off',4,BinHex],
])

AnnotationsDirectoryItem = Entry.create('AnnotationsDirectoryItem',[
        ['class_annotations_off',4,BinHex],
        ['fields_size',4,BinInt],
        ['annotated_methods_size',4,BinInt],
        ['annotated_parameters_size',4,BinInt],
        ['field_annotations','fields_size',EntryList,FieldAnnotation],
        ['method_annotations','annotated_methods_size',EntryList,MethodAnnotation],
        ['parameter_annotations','annotated_parameters_size',EntryList,ParameterAnnotation],
])

AnnotationSetRefItem = Entry.create('AnnotationSetRefItem',[
        ['annotations_off',4,BinHex],
])

AnnotationSetRefList = Entry.create('AnnotationSetRefList',[
        ['size',4,BinInt],
        ['list','size',EntryList,AnnotationSetRefItem],
])

AnnotationOffItem = Entry.create('AnnotationOffItem',[
        ['annotation_off',4,BinHex]
])

AnnotationSetItem = Entry.create('AnnotationSetItem',[
        ['size',4,BinInt],
        ['entries','size',EntryList,AnnotationOffItem],
])

AnnotationItem = Entry.create('AnnotationItem',[
        ['visibility',1,BinData],
        ['annotation',1,EncodedAnnotation],
])

EncodedArrayItem = Entry.create('EncodedArrayItem',[
        ['value',1,EncodedArray],
])
