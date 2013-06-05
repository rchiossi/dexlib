#!/usr/bin/python

from libparse.bindata import BinData

#Utility Classes - Used for the Printer
class BinMapType(BinData):
    def __str__(self):    
        type_map = {
            0x0000:'TYPE_HEADER_ITEM',
            0x0001:'TYPE_STRING_ID_ITEM',
            0x0002:'TYPE_TYPE_ID_ITEM',
            0x0003:'TYPE_PROTO_ID_ITEM',
            0x0004:'TYPE_FIELD_ID_ITEM',
            0x0005:'TYPE_METHOD_ID_ITEM',
            0x0006:'TYPE_CLASS_DEF_ITEM',
            0x1000:'TYPE_MAP_LIST',
            0x1001:'TYPE_TYPE_LIST',
            0x1002:'TYPE_ANNOTATION_SET_REF_LIST',
            0x1003:'TYPE_ANNOTATIONS_DIRECTORY_ITEM',
            0x2000:'TYPE_CLASS_DATA_ITEM',
            0x2001:'TYPE_CODE_ITEM',
            0x2002:'TYPE_STRING_DATA_ITEM',
            0x2003:'TYPE_DEBUG_INFO_ITEM',
            0x2004:'TYPE_ANNOTATION_ITEM',
            0x2005:'TYPE_ENCODED_ARRAY_ITEM',
            0x2006:'TYPE_ANNOTATIONS_DIRECTORY_ITEM',
        }

        if int(self) in type_map.keys():
            return type_map[int(self)]

        return 'TYPE_UNKNOWN'
