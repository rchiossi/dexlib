#!/usr/bin/python

from libparse.bindata import BinData
from libparse.bytestream import ByteStream

from libparse.entry import EntryList
from libparse.entry import EntryTable

from dex_entries import *

#Entry(bstream,offset)
#EntryList(bstream,size,entry_type,offset)
#EntryTable(bstream,elist,etype,offset_field)

class Dex(object):
    """Dex Object"""

    def __init__(self):
        self.header = None

    def parse(self,data):
        bstream = ByteStream(data)

        self.header = Header(bstream,0)

        self.map_list = MapList(bstream,self.header.map_off)

        self.string_ids = EntryList(bstream, StringId,
                                    self.header.string_ids_size,
                                    self.header.string_ids_off)

        self.type_ids = EntryList(bstream, TypeId,
                                  self.header.type_ids_size,
                                  self.header.type_ids_off)

        self.proto_ids = EntryList(bstream, ProtoId,
                                   self.header.proto_ids_size,
                                   self.header.proto_ids_off)

        self.field_ids = EntryList(bstream, FieldId,
                                   self.header.field_ids_size,
                                   self.header.field_ids_off)

        self.method_ids = EntryList(bstream, MethodId,
                                    self.header.method_ids_size,
                                    self.header.method_ids_off)

        self.class_defs = EntryList(bstream, ClassDef,
                                    self.header.class_defs_size,
                                    self.header.class_defs_off)

        #StringId data
        self.string_data_table = EntryTable(bstream, StringData,
                                            self.string_ids,'string_data_off')

        #ProtoId data
        self.type_list_table = EntryTable(bstream, TypeList,
                                          self.proto_ids,'parameters_off',0)

        #ClassDef data        
        self.type_list_table.parse_list(bstream,self.class_defs,'interfaces_off',0)

        self.annotations_directory_item_table = EntryTable(bstream,
                                                           AnnotationsDirectoryItem,
                                                           self.class_defs,
                                                           'annotations_off',0)

        self.class_data_table = EntryTable(bstream, ClassData,
                                           self.class_defs,'class_data_off',0)

        self.encoded_array_table = EntryTable(bstream, EncodedArrayItem,
                                              self.class_defs,'static_values_off',0)

        #ClassData data
        self.code_item_table = EntryTable(bstream, CodeItem) 

        for class_data in self.class_data_table.data:
            self.code_item_table.parse_list(bstream, class_data.direct_methods,
                                            'code_off',0)

            self.code_item_table.parse_list(bstream, class_data.virtual_methods,
                                            'code_off',0)
        
        #CodeItem data
        self.debug_info_item_table = EntryTable(bstream, DebugInfoItem,
                                                self.code_item_table, 
                                                'debug_info_off', 0)

        self.encoded_catch_handler = EntryTable(bstream, EncodedCatchHandler)
       
                                                
        
