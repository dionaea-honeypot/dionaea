# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter & Mark Schloesser
# SPDX-FileCopyrightText: 2010 Markus Koetter & Tan Kean Siong
# SPDX-FileCopyrightText: 2015 Katarina Durechova
# SPDX-FileCopyrightText: 2017 Tan Kean Siong
# SPDX-FileCopyrightText: 2016-2017 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import tempfile

from uuid import UUID
from time import time, localtime, altzone

from dionaea import ndrlib
from dionaea.core import g_dionaea, incident
from .include.smbfields import DCERPC_Header, DCERPC_Response

rpclog = logging.getLogger('rpcservices')

# Set the operating system of Dionaea by changing the value
# Default value is 2
# 1:"Windows XP Service Pack 0/1",
# 2:"Windows XP Service Pack 2",
# 3:"Windows XP Service Pack 3",
# 4:"Windows 7 Service Pack 1",
# 5:"Linux Samba 4.3.11"
OS_TYPE = 2

class DCERPCValueError(Exception):
    """Raised when an a value is passed to a dcerpc operation which is invalid"""

    def __init__(self, varname, reason, value):
        self.varname = varname
        self.reason = reason
        self.value = value
    def __str__(self):
        return "%s is %s (%s)" % (self.varname, self.reason, self.value)


class RPCService(object):
    uuid = ''
    version_major = 0
    version_minor = 0
    # syntax = UUID('8a885d04-1ceb-11c9-9fe8-08002b104860').hex
    ops = {}
    vulns = {}

    @classmethod
    def processrequest(cls, service, con, opnum, p):
        if opnum in cls.ops:
            opname = cls.ops[opnum]

            method = getattr(cls, "handle_" + opname, None)
            if method != None:
                if opnum in cls.vulns:
                    vulnname = cls.vulns[opnum]
                    rpclog.info("Calling %s %s (%x) maybe %s exploit?" % (
                        service.__class__.__name__,  opname, opnum, vulnname ) )
                else:
                    rpclog.info("Calling %s %s (%x)" %
                                ( service.__class__.__name__,  opname, opnum ) )

                r = DCERPC_Header() / DCERPC_Response()

                try:
                    data = method(con, p)
                except DCERPCValueError as e:
                    rpclog.debug("DCERPCValueError %s" % e)
                    return None
                except EOFError as e:
                    rpclog.warn("EOFError data %s" % format(p.StubData))
                    return None

                if data is None:
                    data = b''

                #for metasploit OS type 'Windows XP Service Pack 2+"
                if OS_TYPE == 2 or OS_TYPE == 3:
                    if opname == "NetNameCanonicalize":
                        r.PacketType = 3

                r.StubData = data
                r.AllocHint = len(data)
                r.CallID = p.CallID
                r.FragLen = 24 + len(data)
                rpclog.debug(data)
#				print(r.show())
                return r
        else:
            rpclog.info("Unknown RPC Call to %s %i" %
                        ( service.__class__.__name__,  opnum) )

class ATSVC(RPCService):
    uuid = UUID('1ff70682-0a51-30e8-076d-740be8cee98b').hex

    ops = {
        0x02: "NetrJobEnum",

    }

    class ATSVC_HANDLE(object):
        # 2.3.2 ATSVC_HANDLE
        #
        # http://msdn.microsoft.com/en-us/library/cc248473%28PROT.13%29.aspx
        #
        #typedef [handle] const wchar_t* ATSVC_HANDLE;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                pass
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Pointer = p.unpack_pointer()
                self.Handle = p.unpack_string()
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                pass

    #this function have not tested for the moment
    @classmethod
    def handle_NetrJobEnum(cls, con, p):
        # 3.2.5.2.3 NetrJobEnum (Opnum 2)
        #
        # http://msdn.microsoft.com/en-us/library/cc248425%28PROT.10%29.aspx
        #
        #NET_API_STATUS NetrJobEnum(
        #  [in, string, unique] ATSVC_HANDLE ServerName,
        #  [in, out] LPAT_ENUM_CONTAINER pEnumContainer,
        #  [in] DWORD PreferedMaximumLength,
        #  [out] LPDWORD pTotalEntries,
        #  [in, out, unique] LPDWORD pResumeHandle
        #);

        x = ndrlib.Unpacker(p.StubData)
        ServerName = ATSVC.ATSVC_HANDLE(x)

        Pad = x.unpack_short()
        # pEnumContainer
        EntriesRead = x.unpack_long()
        pEntries = x.unpack_pointer()
        # PreferedMaximumLength
        PreferedMaxLength = x.unpack_long()
        # pResumeHandle
        Pointer = x.unpack_pointer()
        ResumeHandle = x.unpack_long()

        r = ndrlib.Packer()
        # pEnumContainer
        r.pack_long(0)		# EntriesRead
        r.pack_pointer(0)	# pEntries
        # pTotalEntries
        r.pack_long(0)
        # pResumeHandle
        r.pack_pointer(0x0016c918)
        r.pack_long(0)

        # return
        r.pack_long(0)

        return r.get_buffer()


class AudioSrv(RPCService):
    uuid = UUID('3faf4738-3a21-4307-b46c-fdda9bb8c0d5').hex


class browser(RPCService):
    uuid = UUID('6bffd098-a112-3610-9833-012892020162').hex


class davclntrpc(RPCService):
    uuid = UUID('c8cb7687-e6d3-11d2-a958-00c04f682e16').hex


class DCOM(RPCService):
    uuid = UUID('4d9f4ab8-7d1c-11cf-861e-0020af6e7c57').hex

    ops = {
        0x00: "RemoteActivation",
    }
    vulns = {
        0x00: "MS03-26",
    }

    @classmethod
    def handle_RemoteActivation(cls,  con, p):
        # MS03-026
        pass


class DnsServer(RPCService):
    uuid = UUID('50abc2a4-574d-40b3-9d66-ee4fd5fba076').hex


class DSSETUP(RPCService):
    uuid = UUID('3919286a-b10c-11d0-9ba8-00c04fd92ef5').hex

    ops = {
        0x09: "DsRolerUpgradeDownlevelServer"
    }
    vulns  = {
        0x09: "MS04-11",
    }

    @classmethod
    def handle_DsRolerUpgradeDownlevelServer(cls,  con, p):
        # MS04-011
        pass


class epmp(RPCService):
    uuid = UUID('e1af8308-5d1f-11c9-91a4-08002b14a0fa').hex


class eventlog(RPCService):
    uuid = UUID('82273fdc-e32a-18c3-3f78-827929dc23ea').hex


class GetUserToken(RPCService):
    uuid = UUID('a002b3a0-c9b7-11d1-ae88-0080c75e4ec1').hex


class ICertPassage(RPCService):
    uuid = UUID('91ae6020-9e3c-11cf-8d7c-00aa00c091be').hex


class ICertProtect(RPCService):
    uuid = UUID('0d72a7d4-6148-11d1-b4aa-00c04fb66ea0').hex


class InitShutdown(RPCService):
    uuid = UUID('894de0c0-0d55-11d3-a322-00c04fa321a1').hex


class IKeySvc(RPCService):
    uuid = UUID('8d0ffe72-d252-11d0-bf8f-00c04fd9126b').hex


class IPStoreProv(RPCService):
    uuid = UUID('c9378ff1-16f7-11d0-a0b2-00aa0061426a').hex


class ISeclogon(RPCService):
    uuid = UUID('12b81e99-f207-4a4c-85d3-77b42f76fd14').hex


class ISystemActivator(RPCService):
    uuid = UUID('000001a0-0000-0000-c000-000000000046').hex

    ops = {
        0x4: "RemoteCreateInstance"
    }
    vulns  = {
        0x4: "MS04-12",
    }

    @classmethod
    def handle_RemoteCreateInstance(cls, con, p):
        # MS04-012
        pass

class RPC_C_AUTHN(object):
    # http://msdn.microsoft.com/en-us/library/ms692656%28VS.85%29.aspx
    # seems globally used
    NONE = 0
    DCE_PRIVATE = 1
    DCE_PUBLIC = 2
    DEC_PUBLIC = 4
    GSS_NEGOTIATE = 9
    WINNT = 10
    GSS_SCHANNEL = 14
    GSS_KERBEROS = 16
    DEFAULT = 0xFFFFFFFF

class NCACN(object):
    # http://www.opengroup.org/onlinepubs/9692999399/apdxi.htm#tagtcjh_51
    UDP =8
    IP = 9

class IOXIDResolver(RPCService):
    """[MS-DCOM]: Distributed Component Object Model (DCOM) Remote Protocol Specification

    http://msdn.microsoft.com/en-us/library/cc226801%28PROT.10%29.aspx"""


    uuid = UUID('99fcfec4-5260-101b-bbcb-00aa0021347a').hex
    ops = {
        0x5: "ServerAlive2"
    }

    class COMVERSION(object):
        # typedef struct tagCOMVERSION {
        # 	unsigned short MajorVersion;
        # 	unsigned short MinorVersion;
        # } COMVERSION;

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.MajorVersion = 5
                self.MinorVersion = 7

        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_short(self.MajorVersion)
                self.__packer.pack_short(self.MinorVersion)

        def size(self):
            return 4

    class DUALSTRINGARRAY(object):
        # 2.2.1.19.2 DUALSTRINGARRAY
        #
        # http://msdn.microsoft.com/en-us/library/cc226841%28PROT.10%29.aspx
        #
        # typedef struct tagDUALSTRINGARRAY {
        # 	unsigned short wNumEntries;
        # 	unsigned short wSecurityOffset;
        # 	[size_is(wNumEntries)] unsigned short aStringArray[];
        # } DUALSTRINGARRAY;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.NumEntries = 0
                self.SecurityOffset = 0
                self.StringArray = []

        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.NumEntries=self.SecurityOffset=0
                for x in self.StringArray:
                    rpclog.debug("x %s %i" % (x, x.size()))
                    xs = x.size()
                    if isinstance(x, IOXIDResolver.STRINGBINDING):
                        self.SecurityOffset += xs
                    self.NumEntries += xs
                self.__packer.pack_short(int((self.NumEntries+4)/2))
                self.__packer.pack_short(int((self.SecurityOffset+2)/2))

                for i in self.StringArray:
                    if isinstance(i, IOXIDResolver.STRINGBINDING):
                        i.pack()
                self.__packer.pack_raw(b'\0\0')

                for i in self.StringArray:
                    if isinstance(i, IOXIDResolver.SECURITYBINDING):
                        i.pack()
                self.__packer.pack_raw(b'\0\0')


        def size(self):
            return 2 + 2 + sum([x.size() for x in self.StringArray]) + 2 + 2


    class STRINGBINDING(object):
        # 2.2.1.19.3 STRINGBINDING
        #
        # http://msdn.microsoft.com/en-us/library/cc226838%28PROT.10%29.aspx
        #
        # fixmetypdef struct {
        # 	unsigned short wTowerId
        # 	char *aNetworkAddr
        # } STRINGBINDING;
        #
        # TowerId ->
        # http://www.opengroup.org/onlinepubs/9692999399/apdxi.htm#tagcjh_28


        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.TowerId = NCACN.IP
                self.NetworkAddr = ''

        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_short(self.TowerId)
                self.__packer.pack_raw(self.NetworkAddr.encode('utf16')[2:])
                self.__packer.pack_raw(b'\0\0')

        def size(self):
            return 2 + len(self.NetworkAddr.encode('utf16')[2:]) + 2

    class SECURITYBINDING(object):
        # 2.2.1.19.4 SECURITYBINDING
        #
        # http://msdn.microsoft.com/en-us/library/cc226839%28PROT.10%29.aspx
        #
        # fixmetypedef struct {
        # 	unsigned short wAuthnSvc
        #	unsigned short Reserved
        #	wchar_t aPrincName

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.AuthnSvc = RPC_C_AUTHN.GSS_NEGOTIATE
                self.Reserved = 0xffff
                self.PrincName = 'none'

        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_short(self.AuthnSvc)
                if self.AuthnSvc != RPC_C_AUTHN.NONE:
                    self.__packer.pack_short(self.Reserved)
                    self.__packer.pack_raw(self.PrincName.encode('utf16')[2:])
                    self.__packer.pack_raw(b'\0\0')

        def size(self):
            return 2 + 2 + len(self.PrincName.encode('utf16')[2:]) + 2

    @classmethod
    def handle_ServerAlive2(cls, con, dce):

        # http://msdn.microsoft.com/en-us/library/cc226953%28PROT.10%29.aspx
        #
        #	[idempotent] error_status_t ServerAlive2(
        #	  [in] handle_t hRpc,
        #	  [out, ref] COMVERSION* pComVersion,
        #	  [out, ref] DUALSTRINGARRAY** ppdsaOrBindings,
        #	  [out, ref] DWORD* pReserved
        #	);
        p = ndrlib.Packer()

        # prepare values

        ComVersion = IOXIDResolver.COMVERSION(p)

        # the DUALSTRINGARRAY
        dsa = IOXIDResolver.DUALSTRINGARRAY(p)

        s = IOXIDResolver.STRINGBINDING(p)
        s.NetworkAddr = '127.0.0.1'
        dsa.StringArray.append(s)

        s = IOXIDResolver.STRINGBINDING(p)
        s.NetworkAddr = '127.0.0.2'
        dsa.StringArray.append(s)

        s = IOXIDResolver.SECURITYBINDING(p)
        s.AuthnSvc = RPC_C_AUTHN.GSS_NEGOTIATE
        s.PrincName = "OEMCOMPUTER"	# fixme: config value?
        dsa.StringArray.append(s)

        # we are done, pack it

        # ComVersion
        ComVersion.pack()

        # pointer to DUALSTRINGARRAY
        p.pack_pointer(0x200008)

        # DUALSTRINGARRAY size
        p.pack_long(int(dsa.size()/2))

        # DUALSTRINGARRAY
        dsa.pack()

        # reserved
        p.pack_pointer(0x4711)
        p.pack_long(0)

        return p.get_buffer()


class llsrpc(RPCService):
    uuid = UUID('342cfd40-3c6c-11ce-a893-08002b2e9c6d').hex


class lsarpc(RPCService):
    uuid = UUID('12345778-1234-abcd-ef00-0123456789ab').hex

    class LSAPR_HANDLE(object):
        # 2.2.2.1 LSAPR_HANDLE
        #
        # http://msdn.microsoft.com/en-us/library/cc234257%28v=PROT.10%29.aspx
        #
        #typedef [context_handle] void* LSAPR_HANDLE;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Handle = b''
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Value = p.unpack_raw(20)
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_raw(self.Handle)

    class LSAPR_OBJECT_ATTRIBUTES(object):
        # 2.2.9 LSAPR_OBJECT_ATTRIBUTES
        #
        #http://help.outlook.com/en-us/140/cc234450%28PROT.10%29.aspx
        #
        #typedef struct _LSAPR_OBJECT_ATTRIBUTES {
        #  unsigned long Length;
        #  unsigned char* RootDirectory;
        #  PSTRING ObjectName;
        #  unsigned long Attributes;
        #  PLSAPR_SECURITY_DESCRIPTOR SecurityDescriptor;
        #  PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
        #} LSAPR_OBJECT_ATTRIBUTES,
        # *PLSAPR_OBJECT_ATTRIBUTES;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                pass
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Length = self.__packer.unpack_long()
                rpclog.debug("Length = %i" % self.Length)
                self.RootDirectory = self.__packer.unpack_short()
                rpclog.debug("RootDirectory = %x" % self.RootDirectory)
                self.ObjectName = self.__packer.unpack_pointer()
                rpclog.debug("ObjectName = %x" % self.ObjectName)
                self.Attributes = self.__packer.unpack_long()
                self.SecurityDescriptor = self.__packer.unpack_pointer()
                self.SecurityQualityOfService = self.__packer.unpack_pointer()

    class LSA_TRANSLATED_SID(object):
        #http://msdn.microsoft.com/en-us/library/dd424381.aspx
        #
        #typedef struct {
        #  SID_NAME_USE Use;
        #  ULONG RelativeId;
        #  LONG DomainIndex;
        #} LSA_TRANSLATED_SID,
        # *PLSA_TRANSLATED_SID;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Use = 0
                self.RelativeId = 0
                self.DomainIndex = 0
            elif isinstance(self.__packer,ndrlib.Unpacker):
                pass
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_short(self.Use)
                self.__packer.pack_long(self.RelativeId)
                self.__packer.pack_long(self.DomainIndex)
                # unknown
                self.__packer.pack_long(0)

    class LSAPR_TRANSLATED_SIDS(object):
        # 2.2.15 LSAPR_TRANSLATED_SIDS
        #
        #http://msdn.microsoft.com/en-us/library/cc234457%28PROT.10%29.aspx
        #
        #typedef struct _LSAPR_TRANSLATED_SIDS {
        #  [range(0,1000)] unsigned long Entries;
        #  [size_is(Entries)] PLSA_TRANSLATED_SID Sids;
        #} LSAPR_TRANSLATED_SIDS,
        # *PLSAPR_TRANSLATED_SIDS;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Entries = 0
                self.Pointer = 0x3456
                self.MaxCount = 0
                self.Data = []
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Entries = self.__packer.unpack_long()
                rpclog.debug("Entries = %i" % self.Entries)
                self.Pointer = self.__packer.unpack_pointer()
                self.MaxCount = self.__packer.unpack_long()
                if self.Entries != 0:
                    Sids = lsarpc.LSA_TRANSLATED_SID(self.__packer)
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_long(self.Entries)
                rpclog.debug("Entries = %i" % self.Entries)
                self.__packer.pack_pointer(self.Pointer)
                self.__packer.pack_long(self.Entries)
                for i in range(self.Entries):
                    Sids = lsarpc.LSA_TRANSLATED_SID(self.__packer)
                    Sids.pack()


    class LSAPR_TRUST_INFORMATION(object):
        #2.2.11 LSAPR_TRUST_INFORMATION
        #
        #http://msdn.microsoft.com/en-us/library/cc234452%28PROT.10%29.aspx
        #
        #typedef struct _LSAPR_TRUST_INFORMATION {
        #  RPC_UNICODE_STRING Name;
        #  PRPC_SID Sid;
        #} LSAPR_TRUST_INFORMATION,
        # *PLSAPR_TRUST_INFORMATION;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Name = []
                self.Entries = 0
                self.RelativeId = 0
                self.Pointer = 0x11
            elif isinstance(self.__packer,ndrlib.Unpacker):
                pass
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                # MaxCount,needed as the element of NDR array
                self.__packer.pack_long(self.Entries)

                #  RPC_UNICODE_STRING Name;
                for i in range(self.Entries):
                    b = samr.RPC_UNICODE_STRING(self.__packer)
                    b.Data = self.Name[i]
                    b.pack()
                # Pointer to RPC_UNICODE_STRING buffer
                self.__packer.pack_long(self.Pointer)
                # Pointer to RPC_SID buffer
                self.__packer.pack_long(self.Pointer)
                for j in range(self.Entries):
                    self.__packer.pack_string(self.Name[j].encode('utf16')[2:])
                #  PRPC_SID Sid	;
                sid = samr.RPC_SID(self.__packer)
                sid.Value = 'NT_AUTHORITY'
                sid.SubAuthority = ['32','544']
                sid.SubAuthorityCount = len(sid.SubAuthority)

                # Maxcount, needed as the element of NDR array
                self.__packer.pack_long(sid.SubAuthorityCount)
                sid.pack()


    class LSAPR_REFERENCED_DOMAIN_LIST(object):
        # 2.2.12 LSAPR_REFERENCED_DOMAIN_LIST
        #
        #http://msdn.microsoft.com/en-us/library/cc234453%28PROT.13%29.aspx
        #
        #typedef struct _LSAPR_REFERENCED_DOMAIN_LIST {
        #  unsigned long Entries;
        #  [size_is(Entries)] PLSAPR_TRUST_INFORMATION Domains;
        #  unsigned long MaxEntries;
        #} LSAPR_REFERENCED_DOMAIN_LIST,
        # *PLSAPR_REFERENCED_DOMAIN_LIST;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Entries = 0
                self.MaxEntries = 0
                self.Data = []
                self.Pointer = 0x4567
            elif isinstance(self.__packer,ndrlib.Unpacker):
                pass
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_long(self.Entries)
                for i in range(self.Entries):
                    # Pointer
                    self.__packer.pack_long(self.Pointer)
                    # MaxEntries
                    self.__packer.pack_long(0)
                    Domains = lsarpc.LSAPR_TRUST_INFORMATION(self.__packer)
                    Domains.Name = self.Data
                    Domains.Entries = self.Entries
                    Domains.pack()

    class LSAPR_SID_INFORMATION(object):
        # 2.2.17 LSAPR_SID_INFORMATION
        #
        # http://msdn.microsoft.com/en-us/library/cc234459%28v=PROT.10%29.aspx
        #
        #typedef struct _LSAPR_SID_INFORMATION {
        #  PRPC_SID Sid;
        #} LSAPR_SID_INFORMATION,
        # *PLSAPR_SID_INFORMATION
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                pass
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Count = self.__packer.unpack_long()
                Sid = samr.RPC_SID(self.__packer)
        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                pass

    class LSAPR_SID_ENUM_BUFFER(object):
        # 2.2.18 LSAPR_SID_ENUM_BUFFER
        #
        # http://msdn.microsoft.com/en-us/library/cc234460%28PROT.10%29.aspx
        #
        #typedef struct _LSAPR_SID_ENUM_BUFFER {
        #  [range(0,20480)] unsigned long Entries;
        #  [size_is(Entries)] PLSAPR_SID_INFORMATION SidInfo;
        #} LSAPR_SID_ENUM_BUFFER,
        # *PLSAPR_SID_ENUM_BUFFER;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                pass
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Entries = self.__packer.unpack_long()
                self.Pointer = self.__packer.unpack_pointer()
                self.MaxCount = self.__packer.unpack_long()
                for i in range(self.MaxCount):
                    self.Reference = self.__packer.unpack_pointer()
                for j in range(self.MaxCount):
                    SidInfo = lsarpc.LSAPR_SID_INFORMATION(self.__packer)

        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                pass

    class LSAPR_TRANSLATED_NAME_EX(object):
        #2.2.21 LSAPR_TRANSLATED_NAME_EX
        #
        #http://msdn.microsoft.com/en-us/library/cc234463%28v=PROT.13%29.aspx
        #
        #typedef struct _LSAPR_TRANSLATED_NAME_EX {
        #  SID_NAME_USE Use;
        #  RPC_UNICODE_STRING Name;
        #  long DomainIndex;
        #  unsigned long Flags;
        #} LSAPR_TRANSLATED_NAME_EX,
        # *PLSAPR_TRANSLATED_NAME_EX;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                #2.2.13 SID_NAME_USE
                # http://msdn.microsoft.com/en-us/library/cc234454%28v=PROT.13%29.aspx
                self.Use = 8 #SidTypeUnknown
                self.Flags = 0
                self.DomainIndex = 0
                self.Data = []
                self.Pointer = 0x11
                self.Entries = 0
            elif isinstance(self.__packer,ndrlib.Unpacker):
                pass
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                for i in range(self.Entries):
                    self.__packer.pack_short(self.Use)
                    Name = samr.RPC_UNICODE_STRING(self.__packer)
                    # Empty String
                    Name.Data = self.Data
                    self.__packer.pack_pointer(0x00)
                    Name.pack()
                    self.__packer.pack_long(self.DomainIndex)
                    self.__packer.pack_long(self.Flags)


    class LSAPR_TRANSLATED_NAMES_EX(object):
        #2.2.22 LSAPR_TRANSLATED_NAMES_EX
        #
        #http://msdn.microsoft.com/en-us/library/cc234464%28PROT.13%29.aspx
        #
        #typedef struct _LSAPR_TRANSLATED_NAMES_EX {
        #  [range(0,20480)] unsigned long Entries;
        #  [size_is(Entries)] PLSAPR_TRANSLATED_NAME_EX Names;
        #} LSAPR_TRANSLATED_NAMES_EX,
        # *PLSAPR_TRANSLATED_NAMES_EX;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Entries = 0
                self.Data = []
                self.Pointer = 0x6879
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Entries = self.__packer.unpack_long()
                self.Pointer = self.__packer.unpack_pointer()
                if self.Entries != 0:
                    Sids = lsarpc.LSAPR_TRANSLATED_NAMES_EX(self.__packer)
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_long(self.Entries)
                self.__packer.pack_pointer(self.Pointer)
                self.__packer.pack_long(self.Entries)
                Names = lsarpc.LSAPR_TRANSLATED_NAME_EX(self.__packer)
                Names.Entries = self.Entries
                Names.pack()

    ops = {
        0: "Close",
        44: "OpenPolicy",
        57: "LookupSids2",
        58: "LookupNames2"
    }

    @classmethod
    def handle_OpenPolicy(cls, con, p):
        # 3.1.4.4.1 LsarOpenPolicy2 (Opnum 44)
        #
        # http://msdn.microsoft.com/en-us/library/cc234337%28PROT.10%29.aspx
        #
        #NTSTATUS LsarOpenPolicy2(
        #  [in, unique, string] wchar_t* SystemName,
        #  [in] PLSAPR_OBJECT_ATTRIBUTES ObjectAttributes,
        #  [in] ACCESS_MASK DesiredAccess,
        #  [out] LSAPR_HANDLE* PolicyHandle
        #);

        x = ndrlib.Unpacker(p.StubData)
        PSystemName = x.unpack_pointer()
        SystemName = x.unpack_string()
        rpclog.debug("ServerName %s" % SystemName)

        ObjectAttributes = lsarpc.LSAPR_OBJECT_ATTRIBUTES(x)
        DesiredAccess = x.unpack_long()

        r = ndrlib.Packer()
        PolicyHandle = lsarpc.LSAPR_HANDLE(r)
        PolicyHandle.Handle = b'01234567890123456789'
        PolicyHandle.pack()

        # return
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_LookupNames2(cls, con, p):
        # 3.1.4.7 LsarLookupNames2 (Opnum 58)
        #
        # http://msdn.microsoft.com/en-us/library/cc234494%28PROT.13%29.aspx
        #
        #NTSTATUS LsarLookupNames2(
        #  [in] LSAPR_HANDLE PolicyHandle,
        #  [in, range(0,1000)] unsigned long Count,
        #  [in, size_is(Count)] PRPC_UNICODE_STRING Names,
        #  [out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
        #  [in, out] PLSAPR_TRANSLATED_SIDS_EX TranslatedSids,
        #  [in] LSAP_LOOKUP_LEVEL LookupLevel,
        #  [in, out] unsigned long* MappedCount,
        #  [in] unsigned long LookupOptions,
        #  [in] unsigned long ClientRevision
        #);

        x = ndrlib.Unpacker(p.StubData)
        PolicyHandle = lsarpc.LSAPR_HANDLE(x)
        Count = x.unpack_long()

        # Maxcount, needed as the element of NDR array
        MaxCount = x.unpack_long()
        Names = samr.RPC_UNICODE_STRING(x,MaxCount)
        TranslatedSids = lsarpc.LSAPR_TRANSLATED_SIDS(x)

        LookupLevel = x.unpack_short()
        MappedCount = x.unpack_long()
        LookupOptions = x.unpack_long()
        ClientRevision = x.unpack_long()

        r = ndrlib.Packer()
        r.pack_pointer(0x23456)

        ReferenceDomains = lsarpc.LSAPR_REFERENCED_DOMAIN_LIST(r)
        ReferenceDomains.Data = ['HOMEUSER-3AF6FE']
        ReferenceDomains.Entries = len(ReferenceDomains.Data)
        ReferenceDomains.pack()

        Sids = lsarpc.LSAPR_TRANSLATED_SIDS(r)
        Sids.Entries = Count
        Sids.pack()

        # MappedCount
        r.pack_long(3)
        # Return
        r.pack_pointer(0x00000107) #STATUS_SOME_NOT_MAPPED

        return r.get_buffer()

    @classmethod
    def handle_LookupSids2(cls, con, p):
        # 3.1.4.10 LsarLookupSids2 (Opnum 57)
        #
        # http://msdn.microsoft.com/en-us/library/cc234487%28PROT.13%29.aspx
        #
        #NTSTATUS LsarLookupSids2(
        #  [in] LSAPR_HANDLE PolicyHandle,
        #  [in] PLSAPR_SID_ENUM_BUFFER SidEnumBuffer,
        #  [out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
        #  [in, out] PLSAPR_TRANSLATED_NAMES_EX TranslatedNames,
        #  [in] LSAP_LOOKUP_LEVEL LookupLevel,
        #  [in, out] unsigned long* MappedCount,
        #  [in] unsigned long LookupOptions,
        #  [in] unsigned long ClientRevision
        #);

        x = ndrlib.Unpacker(p.StubData)
        PolicyHandle = lsarpc.LSAPR_HANDLE(x)
        SidEnumBuffer = lsarpc.LSAPR_SID_ENUM_BUFFER(x)
        rpclog.debug("EntriesRead = %i" % SidEnumBuffer.Entries)
        TranslatedNames = lsarpc.LSAPR_TRANSLATED_NAMES_EX(x)

        LookupLevel = x.unpack_short()
        MappedCount = x.unpack_long()
        LookupOptions = x.unpack_long()
        ClientRevision = x.unpack_long()
        rpclog.debug ("LookupLevel %i MappedCount %i LookupOptions %i ClientRevision %i" %(
            LookupLevel,MappedCount,LookupOptions,ClientRevision))

        r = ndrlib.Packer()
        r.pack_pointer(0x23456)

        ReferenceDomains = lsarpc.LSAPR_REFERENCED_DOMAIN_LIST(r)
        ReferenceDomains.Data = ['HOMEUSER-3AF6FE']
        ReferenceDomains.Entries = len(ReferenceDomains.Data)
        ReferenceDomains.pack()

        # Nmap smb-enum-users.nse scanning will simply return none of the
        # element has translated, ugly but it works for the moment
        TranslatedNames = lsarpc.LSAPR_TRANSLATED_NAMES_EX(r)
        TranslatedNames.Entries = SidEnumBuffer.Entries
        TranslatedNames.pack()

        # return
        r.pack_long(0)
        r.pack_pointer(0xc0000073) #STATUS_NONE_MAPPED

        return r.get_buffer()

    @classmethod
    def handle_Close(cls, con, p):
        #3.1.4.3 LsarClose (Opnum 0)
        #
        #http://msdn.microsoft.com/en-us/library/cc234490%28v=PROT.13%29.aspx
        #
        #NTSTATUS LsarClose(
        #  [in, out] LSAPR_HANDLE* ObjectHandle
        #);
        x = ndrlib.Unpacker(p.StubData)
        ObjectHandle = lsarpc.LSAPR_HANDLE(x)
        rpclog.debug("ObjectHandle %s" % ObjectHandle)

        r = ndrlib.Packer()
        s = lsarpc.LSAPR_HANDLE(r)
        s.Handle =  b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
        s.pack()
        r.pack_long(0)

        return r.get_buffer()


class msgsvcsend(RPCService):
    uuid = UUID('5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc').hex


class MSMQ(RPCService):
    uuid = UUID('fdb3a030-065f-11d1-bb9b-00a024ea5525').hex

    ops = {
        0x06: "QMCreateObjectInternal",
        0x09: "QMDeleteObject",
    }
    vulns = {
        0x06: "MS07-065",
        0x09: "MS05-017",
    }

    @classmethod
    def handle_QMCreateObjectInternal(cls, con, p):
        # MS07-065
        pass

    @classmethod
    def handle_QMDeleteObject(cls, con, p):
        # MS05-017
        pass


class netdfs(RPCService):
    uuid = UUID('4fc742e0-4a10-11cf-8273-00aa004ae673').hex


class netlogon(RPCService):
    uuid = UUID('12345678-1234-abcd-ef00-01234567cffb').hex


class nddeapi(RPCService):
    uuid = UUID('2f5f3220-c126-1076-b549-074d078619da').hex
    ops = {
        0x0c: "NDdeSetTrustedShareW"
    }

    vulns = {
        0x0c: "MS04-031"
    }

    @classmethod
    def handle_NDdeSetTrustedShareW(cls, con, p):
        # MS04-031
        pass



class NWWKS(RPCService):
    uuid = UUID('e67ab081-9844-3521-9d32-834f038001c0').hex

    ops = {
        0x09: "NwOpenEnumNdsSubTrees",
        0x01: "NwChangePassword"
    }
    vulns  = {
        0x09: "MS06-66",
        0x01: "MS06-66",
    }

    @classmethod
    def handle_NwOpenEnumNdsSubTrees(cls, con, p):
        # MS06-066
        pass

    @classmethod
    def handle_NwChangePassword(cls, con, p):
        # MS06-066
        pass


class NsiS(RPCService):
    uuid = UUID('d6d70ef0-0e3b-11cb-acc3-08002b1d29c4').hex


class PNP(RPCService):
    uuid = UUID('8d9f4e40-a03d-11ce-8f69-08003e30051b').hex

    ops = {
        0x36: "PNP_QueryResConfList",
    }
    vulns = {
        0x36: "MS05-39",
    }

    @classmethod
    def handle_PNP_QueryResConfList(cls, con, p):
        # MS05-39
        pass



class PolicyAgent(RPCService):
    uuid = UUID('d335b8f6-cb31-11d0-b0f9-006097ba4e54').hex


class pmapapi(RPCService):
    uuid = UUID('369ce4f0-0fdc-11d3-bde8-00c04f8eee78').hex


class RemoteAccess(RPCService):
    uuid = UUID('8f09f000-b7ed-11ce-bbd2-00001a181cad').hex

class MGMT(RPCService):
    """ Remote Management Interface
    http://www.opengroup.org/onlinepubs/9629399/apdxq.htm """

    uuid = UUID('afa8bd80-7d8a-11c9-bef4-08002b102989').hex
    ops = {
        0 : "inq_if_ids",
        1 : "inq_stats",
        2 : "is_server_listening",
        3 : "stop_server_listening",
        4 : "inq_princ_name"
    }
# As I lack a way to verify the code, this is commented, maybe samba4
# smbtorture can help out
    class handle_t(object):
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                pass
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.handle = self.__packer.unpack_short()

    class uuid_t(object):
        # typedef struct {
        # 	unsigned32          time_low;
        # 	unsigned16          time_mid;
        # 	unsigned16          time_hi_and_version;
        # 	unsigned8           clock_seq_hi_and_reserved;
        # 	unsigned8           clock_seq_low;
        # 	byte                node[6];
        # } uuid_t, *uuid_p_t;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer = p
                self.time_low = 0
                self.time_mid = 1
                self.time_hi_and_version = 2
                self.clock_seq_hi_and_reserved = 3
                self.clock_seq_low = 4
                self.node = b"56789a"

        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_long(self.time_low)
                self.__packer.pack_short(self.time_mid)
                self.__packer.pack_short(self.time_hi_and_version)
                self.__packer.pack_small(self.clock_seq_hi_and_reserved)
                self.__packer.pack_small(self.clock_seq_low)
                self.__packer.pack_raw(self.node)
        def __str__(self):
            return "123455"

    class rpc_if_id_t(object):
        # typedef struct {
        # 	uuid_t                  uuid;
        # 	unsigned16              vers_major;
        # 	unsigned16              vers_minor;
        # } rpc_if_id_t;
        # typedef [ptr] rpc_if_id_t *rpc_if_id_p_t;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.uuid = MGMT.uuid_t(p)
                self.vers_major = 0
                self.vers_minor = 1
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.uuid.pack()
                self.__packer.pack_short(self.vers_major)
                self.__packer.pack_short(self.vers_minor)
        def show(self):
            rpclog.debug("uuid %s %i.%i" %
                         (self.uuid, self.vers_major, self.vers_minor))

    class rpc_if_id_vector_t(object):
        # typedef struct {
        # 	unsigned32              count;
        # 	[size_is(count)]
        # 	rpc_if_id_p_t           if_id[*];
        # } rpc_if_id_vector_t;
        # typedef [ptr] rpc_if_id_vector_t *rpc_if_id_vector_p_t;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.count = 0
                self.if_id = []
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.count = len(self.if_id)
                self.__packer.pack_long(self.count)
                self.__packer.pack_long(self.count) # maybe array size?
                # pointers ...
                for i in self.if_id:
                    self.__packer.pack_pointer(65)
                # the if_id_vectors
                for i in self.if_id:
                    i.pack()

        def show(self, indent=0):
            rpclog.debug("rpc_if_id_vector_t")
            rpclog.debug("count %i", len(self.if_id))
            for i in self.if_id:
                i.show()
    @classmethod
    def handle_inq_if_ids(cls, con, p):
        #
        # void rpc__mgmt_inq_if_ids
        # (
        # 	[in]        handle_t                binding_handle,
        # 	[out]       rpc_if_id_vector_p_t    *if_id_vector,
        # 	[out]       error_status_t          *status
        # );
        r = ndrlib.Packer()
        r.pack_pointer(0x4747)
        v = MGMT.rpc_if_id_vector_t(r)
        v.if_id.append(MGMT.rpc_if_id_t(r))
        v.show()
        v.pack()
        r.pack_long(0) # return value
        return r.get_buffer()

    @classmethod
    def handle_inq_stats(cls, con, p):
        pass

    @classmethod
    def handle_is_server_listening(cls, con, p):
        pass

    @classmethod
    def handle_stop_server_listening(cls, con, p):
        pass

    @classmethod
    def handle_inq_princ_name(cls, con, p):
        # void rpc__mgmt_inq_princ_name
        # (
        #     [in]        handle_t                binding_handle,
        #     [in]        unsigned32              authn_proto,
        #     [in]        unsigned32              princ_name_size,
        #     [out, string, size_is(princ_name_size)]
        #                 char                    princ_name[],
        #     [out]       error_status_t          *status
        # );
        x = ndrlib.Unpacker(p.StubData)
        handle = MGMT.handle_t(x)
#		authn_proto = x.unpack_long()
#		princ_name_size = x.unpack_long()

        r = ndrlib.Packer()
        r.pack_string(b"oemcomputer")
#		r.pack_long(0)
#		r.pack_long(0)
        return r.get_buffer()



__userinfo__ = {
    'Administrator' : {
        'RID': 500,
        'comment' : 'Built-in account for administering the computer/domain'
    },
    'Guest' : {
        'RID': 501,
        'comment' : 'Built-in account for guest access the computer/domain'
    },
    'HelpAssistant' : {
        'RID': 1000,
        'comment' : 'Account for Providing Remote Assistance'
    },
    'SUPPORT_388945a0' : {
        'RID' : 1002,
        'comment' : 'This is a vendor\'s account for the Help and Support Service'
    }
}


class samr(RPCService):
    """ [MS-SAMR]: Security Account Manager (SAM) Remote Protocol Specification (Client-to-Server)

    http://msdn.microsoft.com/en-us/library/cc245476%28v=PROT.13%29.aspx

    http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-SAMR%5D.pdf"""



    uuid = UUID('12345778-1234-abcd-ef00-0123456789ac').hex

    # Used for SAMR handle_LookupNamesInDomain and handle_QueryInformationUser
    LookupName = ""

    class SAMPR_HANDLE(object):
        # 2.2.3.2 SAMPR_HANDLE
        #
        # http://msdn.microsoft.com/en-us/library/cc245544%28v=PROT.10%29.aspx
        #
        # typedef [context_handle] void* SAMPR_HANDLE;
        #
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Handle = b''
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Value = p.unpack_raw(20)
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_raw(self.Handle)

    class RPC_SID_IDENTIFIER_AUTHORITY(object):
        # 2.4.1.1 RPC_SID_IDENTIFIER_AUTHORITY
        #
        # http://msdn.microsoft.com/en-us/library/cc230372%28PROT.10%29.aspx
        #
        # typedef struct _RPC_SID_IDENTIFIER_AUTHORITY {
        #   byte Value[6];
        # } RPC_SID_IDENTIFIER_AUTHORITY;
        #
        SID_AUTHORITY = {
            'NULL_SID_AUTHORITY'			: b'\x00\x00\x00\x00\x00\x00',
            'WORLD_SID_AUTHORITY'			: b'\x00\x00\x00\x00\x00\x01',
            'LOCAL_SID_AUTHORITY'			: b'\x00\x00\x00\x00\x00\x02',
            'CREATOR_SID_AUTHORITY'			: b'\x00\x00\x00\x00\x00\x03',
            'NON_UNIQUE_AUTHORITY'			: b'\x00\x00\x00\x00\x00\x04',
            'NT_AUTHORITY'				: b'\x00\x00\x00\x00\x00\x05',
            'SECURITY_MANDATORY_LABEL_AUTHORITY'	: b'\x00\x00\x00\x00\x00\x10'
        }
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Value = ''
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Value = self.__packer.unpack_raw(6)
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                if not self.SID_AUTHORITY.get(self.Value) == None:
                    self.__packer.pack_raw(self.SID_AUTHORITY[self.Value])


    class RPC_SID(object):
        # 2.4.2.2 RPC_SID
        #
        # http://msdn.microsoft.com/en-us/library/cc230364%28PROT.10%29.aspx
        #
        # typedef struct _RPC_SID {
        #   unsigned char Revision;
        #   unsigned char SubAuthorityCount;
        #   RPC_SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
        #   [size_is(SubAuthorityCount)]
        #   unsigned long SubAuthority[];
        # } RPC_SID,
        #  *PRPC_SID;
        #
        def __init__(self, p):
            self.__packer = p
            if isinstance(p,ndrlib.Packer):
                self.Value = ''
                self.Revision = 1 # must be 0x01
                self.SubAuthorityCount = 0
                self.SubAuthority = []
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Revision = self.__packer.unpack_small()
                self.SubAuthorityCount = self.__packer.unpack_small()
                self.IdentifierAuthority = samr.RPC_SID_IDENTIFIER_AUTHORITY(
                    self.__packer)
                self.SubAuthority = []
                for i in range(self.SubAuthorityCount):
                    self.SubAuthority.append(p.unpack_long())
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                # Revision
                self.__packer.pack_small(self.Revision)

                # SubAuthorityCount
                self.__packer.pack_small(self.SubAuthorityCount)

                # RPC_SID_IDENTIFIER_AUTHORITY
                b = samr.RPC_SID_IDENTIFIER_AUTHORITY(self.__packer)
                b.Value = self.Value
                b.pack()

                # SubAuthority
                for i in range(self.SubAuthorityCount):
                    self.__packer.pack_long(int(self.SubAuthority[i]))

    class RPC_UNICODE_STRING(object):
        # 2.3.5 RPC_UNICODE_STRING
        #
        # http://msdn.microsoft.com/en-us/library/cc230365%28PROT.10%29.aspx
        #
        # typedef struct _RPC_UNICODE_STRING {
        #   unsigned short Length;
        #   unsigned short MaximumLength;
        #   [size_is(MaximumLength/2), length_is(Length/2)]
        # 	WCHAR* Buffer;
        # } RPC_UNICODE_STRING,
        #  *PRPC_UNICODE_STRING;
        #
        def __init__(self, p, c=1):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Data =[]
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Count = c #specify how many string array
                rpclog.debug("Count = %i" % self.Count)
                for i in range(self.Count):
                    self.Length = self.__packer.unpack_short()
                    self.MaximumLength = self.__packer.unpack_short()
                    self.Reference = self.__packer.unpack_pointer()
                for j in range(self.Count):
                    self.Buffer = self.__packer.unpack_string()
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_rpc_unicode_string(self.Data)


    class SAMPR_RID_ENUMERATION(object):
        # 2.2.3.9 SAMPR_RID_ENUMERATION
        #
        # http://msdn.microsoft.com/en-us/library/cc245560%28PROT.10%29.aspx
        #
        # typedef struct _SAMPR_RID_ENUMERATION {
        #   unsigned long RelativeId;
        #   RPC_UNICODE_STRING Name;
        # } SAMPR_RID_ENUMERATION,
        #  *PSAMPR_RID_ENUMERATION;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Name = []
                self.RelativeId = 0
                self.Pointer = 0x11
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.RelativeId = self.__packer.unpack_long()
                self.Name = samr.RPC_UNICODE_STRING(self.__packer, Name)
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                for i in range(len(self.Name)):
                    #RelativeID
                    self.__packer.pack_long(self.RelativeId)

                    b = samr.RPC_UNICODE_STRING(self.__packer)
                    b.Data = self.Name[i]
                    b.pack()
                    self.__packer.pack_pointer(self.Pointer)

                for j in range(len(self.Name)):
                    self.__packer.pack_string(self.Name[j].encode('utf16')[2:])

    class SAMPR_ENUMERATION_BUFFER(object):
        # 2.2.3.10 SAMPR_ENUMERATION_BUFFER
        #
        # http://msdn.microsoft.com/en-us/library/cc245561%28v=PROT.10%29.aspx
        #
        # typedef struct _SAMPR_ENUMERATION_BUFFER {
        #     unsigned long EntriesRead;
                #    [size_is(EntriesRead)] PSAMPR_RID_ENUMERATION Buffer;
        # } SAMPR_ENUMERATION_BUFFER,
        # *PSAMPR_ENUMERATION_BUFFER;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.EntriesRead = 0
                self.Buffer = []
                self.Pointer = 0x4711
            elif isinstance(self.__packer,ndrlib.Unpacker):
                raise NotImplementedError
        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                # EntriesRead
                self.__packer.pack_long(self.EntriesRead)
                self.__packer.pack_pointer(self.Pointer)

                # Maxcount, needed as NDR array
                self.__packer.pack_long(self.EntriesRead)

                b = samr.SAMPR_RID_ENUMERATION(self.__packer)
                b.Name = self.Buffer
                b.pack()

    class SAMPR_DOMAIN_DISPLAY_USER(object):
        # 2.2.8.2 SAMPR_DOMAIN_DISPLAY_USER
        #
        # http://msdn.microsoft.com/en-us/library/cc245632%28PROT.10%29.aspx
        #
        # typedef struct _SAMPR_DOMAIN_DISPLAY_USER {
        #  unsigned long Index;
        #  unsigned long Rid;
        #  unsigned long AccountControl;
        #  RPC_UNICODE_STRING AccountName;
        #  RPC_UNICODE_STRING AdminComment;
        #  RPC_UNICODE_STRING FullName;
        #} SAMPR_DOMAIN_DISPLAY_USER,
        # *PSAMPR_DOMAIN_DISPLAY_USER;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Name = []
                self.Index = 0
                self.Rid = 0
                # AccountControl
                # http://msdn.microsoft.com/en-us/library/cc245514%28v=PROT.10%29.aspx
                self.AccountControl = 16 # USER_NORMAL_ACCOUNT
                self.Pointer = 0x11
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.RelativeId = self.__packer.unpack_long()
                self.Name = samr.RPC_UNICODE_STRING(self.__packer, Name)
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                for i in range(int(len(self.Name)/3)):
                    #Index
                    self.__packer.pack_long(self.Index)
                    #RelativeID
                    self.__packer.pack_long(self.Rid)
                    #AccountCotrol
                    self.__packer.pack_long(self.AccountControl)

                    for k in range(3):
                        b = samr.RPC_UNICODE_STRING(self.__packer)
                        b.Data = self.Name[i*k]
                        b.pack()
                        self.__packer.pack_pointer(self.Pointer)

                for j in range(len(self.Name)):
                    self.__packer.pack_string(self.Name[j].encode('utf16')[2:])

    class SAMPR_DOMAIN_DISPLAY_USER_BUFFER(object):
        # 2.2.8.7 SAMPR_DOMAIN_DISPLAY_USER_BUFFER
        #
        # http://msdn.microsoft.com/en-us/library/cc245637%28PROT.13%29.aspx
        #
        #typedef struct _SAMPR_DOMAIN_DISPLAY_USER_BUFFER {
        #  unsigned long EntriesRead;
        #  [size_is(EntriesRead)] PSAMPR_DOMAIN_DISPLAY_USER Buffer;
        #} SAMPR_DOMAIN_DISPLAY_USER_BUFFER,
        # *PSAMPR_DOMAIN_DISPLAY_USER_BUFFER;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.EntriesRead = 0
                self.Buffer = []
                self.Pointer = 0x4711
            elif isinstance(self.__packer,ndrlib.Unpacker):
                raise NotImplementedError
        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                # EntriesRead
                self.__packer.pack_long(self.EntriesRead)
                self.__packer.pack_pointer(self.Pointer)

                # Maxcount, needed as NDR array
                self.__packer.pack_long(self.EntriesRead)

                b = samr.SAMPR_DOMAIN_DISPLAY_USER(self.__packer)
                b.Name = self.Buffer
                b.pack()

    class ACCESS_ALLOWED_ACE(object):
        # ACCESS_ALLOWED_ACE Structure
        #
        # http://msdn.microsoft.com/en-us/library/aa374847%28v=vs.85%29.aspx
        #
        # typedef struct _ACCESS_ALLOWED_ACE {
        #  ACE_HEADER  Header;
        #  ACCESS_MASK Mask;
        #  DWORD       SidStart;
        #} ACCESS_ALLOWED_ACE, *PACCESS_ALLOWED_ACE;

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.AceType = 0
                self.AceFlags = 0
                self.AceSize = 20
                self.Mask = 0x0002035b
            elif isinstance(self.__packer,ndrlib.Unpacker):
                raise NotImplementedError
        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                #http://msdn.microsoft.com/en-us/library/aa374919%28v=vs.85%29.aspx
                # typedef struct _ACE_HEADER {
                #  BYTE AceType;
                #  BYTE AceFlags;
                #  WORD AceSize;
                #} ACE_HEADER, *PACE_HEADER;

                self.__packer.pack_small(self.AceType)
                self.__packer.pack_small(self.AceFlags)
                self.__packer.pack_short(self.AceSize)

                # ACCESS_MASK Mask;
                self.__packer.pack_long(self.Mask)

                # DWORD SidStart;
                # for example : SID = S-1-1-0
                SidStart = samr.RPC_SID(self.__packer)
                SidStart.Value = 'WORLD_SID_AUTHORITY'
                SidStart.SubAuthority = ['0']
                SidStart.SubAuthorityCount = len(SidStart.SubAuthority)
                SidStart.pack()

    class ACL(object):
        # ACL Structure
        # http://msdn.microsoft.com/en-us/library/aa374931%28v=vs.85%29.aspx
        #
        # typedef struct _ACL {
        #  BYTE AclRevision;
        #  BYTE Sbz1;
        #  WORD AclSize;
        #  WORD AceCount;
        #  WORD Sbz2;
        #} ACL, *PACL;
        # A complete ACL consists of an ACL structure followed by an ordered
        # list of zero or more access control entries (ACEs).

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.AclRevision = 2
                self.Sbz1 = 0
                self.AclSize = 20
                self.AceCount = 1
                self.Sbz2 = 0
            elif isinstance(self.__packer,ndrlib.Unpacker):
                raise NotImplementedError
        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                # ACL Structure
                self.__packer.pack_small(self.AclRevision)
                self.__packer.pack_small(self.Sbz1)
                self.__packer.pack_short(self.AclSize)
                self.__packer.pack_short(self.AceCount)
                self.__packer.pack_short(self.Sbz2)

                # Followed by a ACCESS_ALLOWED_ACE Structure
                b = samr.ACCESS_ALLOWED_ACE(self.__packer)
                b.pack()

    class SECURITY_DESCRIPTOR(object):
        # 2.4.6 SECURITY_DESCRIPTOR
        #
        # http://msdn.microsoft.com/en-us/library/cc230366%28v=prot.10%29.aspx
        # The documentation only provide the struct details as below:
        #
        # Revision (1 byte)
        # Sbz1 (1 byte)
        # Control (2 bytes)
        # OffsetOwner (4 bytes)
        # OffsetGroup (4 bytes)
        # OffsetSacl (4 bytes)
        # OffsetDacl (4 bytes)
        # OwnerSid (variable)
        # GroupSid (variable)
        # Sacl (variable)
        # Dacl (variable)

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Revision = 1
                self.Sbz1 = 0
                self.Control = 0x8004
                self.OffsetOwner = 0
                self.OffsetGroup = 0
                self.OffsetSacl = 0
                self.OffsetDacl = 20
            elif isinstance(self.__packer,ndrlib.Unpacker):
                raise NotImplementedError
        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                self.__packer.pack_small(self.Revision)
                self.__packer.pack_small(self.Sbz1)
                self.__packer.pack_short(self.Control)
                self.__packer.pack_long(self.OffsetOwner)
                self.__packer.pack_long(self.OffsetGroup)
                self.__packer.pack_long(self.OffsetSacl)
                self.__packer.pack_long(self.OffsetDacl)

                b = samr.ACL(self.__packer)
                b.pack()


    class SAMPR_SR_SECURITY_DESCRIPTOR(object):
        # 2.2.3.11 SAMPR_SR_SECURITY_DESCRIPTOR
        #
        # http://msdn.microsoft.com/en-us/library/cc245537%28v=prot.10%29.aspx
        #
        #typedef struct _SAMPR_SR_SECURITY_DESCRIPTOR {
        #  [range(0, 256 * 1024)] unsigned long Length;
        #  [size_is(Length)] unsigned char* SecurityDescriptor;
        #} SAMPR_SR_SECURITY_DESCRIPTOR,
        # *PSAMPR_SR_SECURITY_DESCRIPTOR;

        def __init__(self, p, c=0):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Length = c
                self.Pointer = 0xd1b00
            elif isinstance(self.__packer,ndrlib.Unpacker):
                raise NotImplementedError
        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                if self.Length == 0:
                    # Support for samr.handle_QueryInformationUser()
                    self.__packer.pack_long(self.Length)
                    self.__packer.pack_pointer(0)

                else:
                    # Support samr.handle_QuerySecurityObject()
                    # Pointer to SecurityDescriptor
                    self.__packer.pack_pointer(self.Pointer)
                    self.__packer.pack_long(self.Length)
                    b = samr.SECURITY_DESCRIPTOR(self.__packer)
                    b.pack()

    class SAMPR_USER_ALL_INFORMATION(object):
        # 2.2.7.6 SAMPR_USER_ALL_INFORMATION
        #
        # http://msdn.microsoft.com/en-us/library/cc245622%28v=prot.10%29.aspx
        #
        #typedef struct _SAMPR_USER_ALL_INFORMATION {
        #  OLD_LARGE_INTEGER LastLogon;
        #  OLD_LARGE_INTEGER LastLogoff;
        #  OLD_LARGE_INTEGER PasswordLastSet;
        #  OLD_LARGE_INTEGER AccountExpires;
        #  OLD_LARGE_INTEGER PasswordCanChange;
        #  OLD_LARGE_INTEGER PasswordMustChange;
        #  RPC_UNICODE_STRING UserName;
        #  RPC_UNICODE_STRING FullName;
        #  RPC_UNICODE_STRING HomeDirectory;
        #  RPC_UNICODE_STRING HomeDirectoryDrive;
        #  RPC_UNICODE_STRING ScriptPath;
        #  RPC_UNICODE_STRING ProfilePath;
        #  RPC_UNICODE_STRING AdminComment;
        #  RPC_UNICODE_STRING WorkStations;
        #  RPC_UNICODE_STRING UserComment;
        #  RPC_UNICODE_STRING Parameters;
        #  RPC_SHORT_BLOB LmOwfPassword;
        #  RPC_SHORT_BLOB NtOwfPassword;
        #  RPC_UNICODE_STRING PrivateData;
        #  SAMPR_SR_SECURITY_DESCRIPTOR SecurityDescriptor;
        #  unsigned long UserId;
        #  unsigned long PrimaryGroupId;
        #  unsigned long UserAccountControl;
        #  unsigned long WhichFields;
        #  SAMPR_LOGON_HOURS LogonHours;
        #  unsigned short BadPasswordCount;
        #  unsigned short LogonCount;
        #  unsigned short CountryCode;
        #  unsigned short CodePage;
        #  unsigned char LmPasswordPresent;
        #  unsigned char NtPasswordPresent;
        #  unsigned char PasswordExpired;
        #  unsigned char PrivateDataSensitive;
        #} SAMPR_USER_ALL_INFORMATION,
        # *PSAMPR_USER_ALL_INFORMATION;

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.LastLogon = 0
                self.LastLogoff = 0
                # Last Password Change = Apr 20,2011 07:32:44 78125000
                self.PasswordLastSet = 0x01cbfeea1590eb94
                self.AccountExpires = 0
                self.PasswordCanChange = 0
                self.PasswordMustChange = 0x7fffffffffffffff
                self.Buffer = []
                self.Pointer = 0x6511
                self.UserId = 0
                self.PrimaryGroupId = 513
                self.UserAccountControl = 0x00000210
                self.WhichFields = 0x00ffffff
                self.UnitsPerWeek = 168
                self.LogonHours = 0xff
                self.BadPasswordCount = 0
                self.LogonCount = 0
                self.CountryCode = 0
                self.CodePage = 0
                self.LmPasswordPresent = 0
                self.NtPasswordPresent = 0
                self.PasswordExpired = 0
                self.PrivateDataSensitive = 0

            elif isinstance(self.__packer,ndrlib.Unpacker):
                raise NotImplementedError
        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                self.__packer.pack_hyper(self.LastLogon)
                self.__packer.pack_hyper(self.LastLogoff)
                self.__packer.pack_hyper(self.PasswordLastSet)
                self.__packer.pack_hyper(self.AccountExpires)
                self.__packer.pack_hyper(self.PasswordCanChange)
                self.__packer.pack_hyper(self.PasswordMustChange)

                for k in range(13):
                    b = samr.RPC_UNICODE_STRING(self.__packer)
                    b.Data = self.Buffer[k]
                    b.pack()
                    self.__packer.pack_pointer(self.Pointer)

                # SAMPR_SR_SECURITY_DESCRIPTOR SecurityDescriptor;
                k = samr.SAMPR_SR_SECURITY_DESCRIPTOR(self.__packer, 0)
                k.pack()

                self.__packer.pack_long(self.UserId)
                self.__packer.pack_long(self.PrimaryGroupId)
                self.__packer.pack_long(self.UserAccountControl)
                self.__packer.pack_long(self.WhichFields)

                # SAMPR_LOGON_HOURS LogonHours;
                # 2.2.7.5 SAMPR_LOGON_HOURS
                # http://msdn.microsoft.com/en-us/library/cc245621%28v=prot.10%29.aspx
                self.__packer.pack_long(self.UnitsPerWeek)
                self.__packer.pack_pointer(self.Pointer)

                self.__packer.pack_short(self.BadPasswordCount)
                self.__packer.pack_short(self.LogonCount)
                self.__packer.pack_short(self.CountryCode)
                self.__packer.pack_short(self.CodePage)
                self.__packer.pack_small(self.LmPasswordPresent)
                self.__packer.pack_small(self.NtPasswordPresent)
                self.__packer.pack_small(self.PasswordExpired)
                self.__packer.pack_small(self.PrivateDataSensitive)

                for j in range(len(self.Buffer)):
                    self.__packer.pack_string(
                        self.Buffer[j].encode('utf16')[2:])
                self.__packer.pack_long(int(self.UnitsPerWeek*60/8))
                self.__packer.pack_long(0)
                self.__packer.pack_long(int(self.UnitsPerWeek/8))

                for l in range(int(self.UnitsPerWeek/8)):
                    self.__packer.pack_small(self.LogonHours)

    class SAMPR_PSID_ARRAY(object):
        # 2.2.3.6 SAMPR_PSID_ARRAY
        #
        # http://msdn.microsoft.com/en-us/library/cc245548%28v=prot.10%29.aspx
        #
        # typedef struct _SAMPR_PSID_ARRAY {
        #  [range(0,1024)] unsigned long Count;
        #  [size_is(Count)] PSAMPR_SID_INFORMATION Sids;
        #} SAMPR_PSID_ARRAY,
        # *PSAMPR_PSID_ARRAY;

        # 2.2.3.5 SAMPR_SID_INFORMATION
        #
        #http://msdn.microsoft.com/en-us/library/cc245547%28v=prot.10%29.aspx
        #
        # typedef struct _SAMPR_SID_INFORMATION {
        #  PRPC_SID SidPointer;
        #} SAMPR_SID_INFORMATION,
        # *PSAMPR_SID_INFORMATION;

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Count1 = 0
                self.Count2 = 0
            elif isinstance(self.__packer,ndrlib.Unpacker):

                self.Count1 = self.__packer.unpack_long()
                for i in range(int(self.Count1)):
                    self.SidPointer = self.__packer.unpack_pointer()
                for j in range(int(self.Count1)):
                    self.Count2 = self.__packer.unpack_long()
                    Sids = samr.RPC_SID(self.__packer)

        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                raise NotImplementedError
    ops = {
        1: "Close",
        3: "QuerySecurityObject",
        5: "LookupDomain",
        6: "EnumDomains",
        7: "OpenDomain",
        13: "EnumDomainUsers",
        15: "EnumerateAliasesInDomain",
        16: "GetAliasMembership",
        17: "LookupNamesInDomain",
        34: "OpenUser",
        36: "QueryInformationUser",
        39: "GetGroupsForUser",
        40: "QueryDisplayInformation",
        46: "QueryInformationDomain2",
        62: "Connect4",
        64: "Connect5"
    }

    @classmethod
    def handle_Connect4(cls, con, p):
        # 3.1.5.1.2 SamrConnect4 (Opnum 62)
        #
        # http://msdn.microsoft.com/en-us/library/cc245746%28PROT.10%29.aspx
        #
        # long SamrConnect4(
        #   [in, unique, string] PSAMPR_SERVER_NAME ServerName,
        #   [out] SAMPR_HANDLE* ServerHandle,
        #   [in] unsigned long ClientRevision,
        #   [in] unsigned long DesiredAccess
        # );
        x = ndrlib.Unpacker(p.StubData)
        PServerName = x.unpack_pointer()
        ServerName = x.unpack_string()
        rpclog.debug("ServerName %s" % ServerName)
        DesiredAccess = x.unpack_long()
        rpclog.debug("DesiredAccess %i" % DesiredAccess)
        ClientRevision = x.unpack_long()
        rpclog.debug("InVersion %i" % ClientRevision)

        r = ndrlib.Packer()

        # ServerHandle
        ServerHandle = samr.SAMPR_HANDLE(r)
        ServerHandle.Handle = b'01234567890123456789'
        ServerHandle.pack()

        # return
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_Connect5(cls, con, p):
        # 3.1.5.1.1 SamrConnect5 (Opnum 64)
        #
        # http://msdn.microsoft.com/en-us/library/cc245745%28PROT.10%29.aspx
        #
        # long SamrConnect5(
        #   [in, unique, string] PSAMPR_SERVER_NAME ServerName,
        #   [in] unsigned long DesiredAccess,
        #   [in] unsigned long InVersion,
        #   [in, switch_is(InVersion)] SAMPR_REVISION_INFO* InRevisionInfo,
        #   [out] unsigned long* OutVersion,
        #   [out, switch_is(*OutVersion)] SAMPR_REVISION_INFO* OutRevisionInfo,
        #   [out] SAMPR_HANDLE* ServerHandle
        # );
        x = ndrlib.Unpacker(p.StubData)
        PServerName = x.unpack_pointer()
        ServerName = x.unpack_string()

        rpclog.debug("ServerName %s" % ServerName)
        DesiredAccess = x.unpack_long()

        rpclog.debug("DesiredAccess %i" % DesiredAccess)
        InVersion = x.unpack_long()
        rpclog.debug("InVersion %i" % InVersion)

        PInRevisionInfo = x.unpack_pointer()

        # 2.2.3.15 SAMPR_REVISION_INFO_V1
        # http://msdn.microsoft.com/en-us/library/cc245541%28v=PROT.10%29.aspx
        Revision = x.unpack_long()
        SupportedFeatures = x.unpack_long()

        rpclog.debug("Revision %i SupportedFeatures %i" %
                     (Revision, SupportedFeatures))

        r = ndrlib.Packer()

        r.pack_pointer(0x1)
        r.pack_long(InVersion)

        r.pack_long(Revision)
        r.pack_long(SupportedFeatures)

        # ServerHandle
        ServerHandle = samr.SAMPR_HANDLE(r)
        ServerHandle.Handle = b'01234567890123456789'
        ServerHandle.pack()

        # return
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_QuerySecurityObject(cls, con, p):
        #3.1.5.12.2 SamrQuerySecurityObject (Opnum 3)
        #
        #http://msdn.microsoft.com/en-us/library/cc245718%28v=PROT.10%29.aspx
        #
        #long SamrQuerySecurityObject(
        #  [in] SAMPR_HANDLE ObjectHandle,
        #  [in] SECURITY_INFORMATION SecurityInformation,
        #  [out] PSAMPR_SR_SECURITY_DESCRIPTOR* SecurityDescriptor
        #);
        x = ndrlib.Unpacker(p.StubData)
        ObjectHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("ObjectHandle %s" % ObjectHandle)

        SecurityInformation = x.unpack_long()
        rpclog.debug("SecurityInformation %i" % SecurityInformation)

        r = ndrlib.Packer()

        # Pointer to struct _SAMPR_SR_SECURITY_DESCRIPTOR
        r.pack_pointer(0xbbe58)

        # FIXME: currently length is hardcoded as 48, make it dynamic if
        # necessary
        Length = 48
        r.pack_long(Length)

        s = samr.SAMPR_SR_SECURITY_DESCRIPTOR(r,Length)
        s.pack()

        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_EnumDomains(cls, con, p):
        #3.1.5.2.1 SamrEnumerateDomainsInSamServer (Opnum 6)
        #
        #http://msdn.microsoft.com/en-us/library/cc245755%28v=PROT.10%29.aspx
        #
        #long SamrEnumerateDomainsInSamServer(
        #   [in] SAMPR_HANDLE ServerHandle,
        #   [in, out] unsigned long* EnumerationContext,
        #   [out] PSAMPR_ENUMERATION_BUFFER* Buffer,
        #   [in] unsigned long PreferedMaximumLength,
        #   [out] unsigned long* CountReturned
        #);
        x = ndrlib.Unpacker(p.StubData)
        ServerHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("ServerHandle %s" % ServerHandle)

        EnumerationContext = x.unpack_long()
        rpclog.debug("EnumerationContext %i" % EnumerationContext)

        PreferedMaximumLength = x.unpack_long()
        rpclog.debug("PreferedMaximumLength %i" % PreferedMaximumLength)

        r = ndrlib.Packer()
        # unsigned long* EnumerationContext,
        r.pack_pointer(EnumerationContext)

        # Pointer to SAMPR_ENUMERATION_BUFFER* Buffer
        r.pack_pointer(0x0da260)

        # SAMPR_ENUMERATION_BUFFER Buffer
        s = samr.SAMPR_ENUMERATION_BUFFER(r)
        s.Buffer = ['HOMEUSER-3AF6FE','Builtin']
        s.EntriesRead = len(s.Buffer)
        s.pack()

        # long* CountReturned
        r.pack_long(s.EntriesRead)
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_LookupDomain(cls, con, p):
        #3.1.5.11.1 SamrLookupDomainInSamServer (Opnum 5)
        #
        #http://msdn.microsoft.com/en-us/library/cc245711%28v=PROT.13%29.aspx
        #
        #long SamrLookupDomainInSamServer(
        #[in] SAMPR_HANDLE ServerHandle,
        #[in] PRPC_UNICODE_STRING Name,
        #[out] PRPC_SID* DomainId
        #);
        x = ndrlib.Unpacker(p.StubData)
        ServerHandle = samr.SAMPR_HANDLE(x)
        Name = samr.RPC_UNICODE_STRING(x)
        r = ndrlib.Packer()
        r.pack_pointer(0x0da260)   #same as EnumDomain

        # http://technet.microsoft.com/en-us/library/cc778824%28WS.10%29.aspx
        # example the SID for the built-in Administrators group : S-1-5-32-544
        DomainId = samr.RPC_SID(r)
        DomainId.Value = 'NT_AUTHORITY'
        DomainId.SubAuthority = ['32','544']
        DomainId.SubAuthorityCount = len(DomainId.SubAuthority)

        # Maxcount, needed as the element of NDR array
        r.pack_long(DomainId.SubAuthorityCount)

        DomainId.pack()

        r.pack_long(0)
        return r.get_buffer()

    @classmethod
    def handle_OpenDomain(cls, con, p):
        # 3.1.5.1.5 SamrOpenDomain (Opnum 7)
        #
        # http://msdn.microsoft.com/en-us/library/cc245748%28v=PROT.10%29.aspx
        #
        # long SamrOpenDomain(
        #   [in] SAMPR_HANDLE ServerHandle,
        #   [in] unsigned long DesiredAccess,
        #   [in] PRPC_SID DomainId,
        #   [out] SAMPR_HANDLE* DomainHandle
        # );
        x = ndrlib.Unpacker(p.StubData)
        ServerHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("ServerHandle %s" % ServerHandle)

        DesiredAccess = x.unpack_long()
        rpclog.debug("DesiredAccess %i" % DesiredAccess)

        DomainId = samr.RPC_SID(x)

        r = ndrlib.Packer()

        DomainHandle = samr.SAMPR_HANDLE(r)
        DomainHandle.Handle = b'11223344556677889900'
        DomainHandle.pack()

        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_EnumDomainUsers(cls, con, p):
        #3.1.5.2.5 SamrEnumerateUsersInDomain (Opnum 13)
        #
        #http://msdn.microsoft.com/en-us/library/cc245759%28v=PROT.13%29.aspx
        #
        #long SamrEnumerateUsersInDomain(
        #[in] SAMPR_HANDLE DomainHandle,
        #[in, out] unsigned long* EnumerationContext,
        #[in] unsigned long UserAccountControl,
        #[out] PSAMPR_ENUMERATION_BUFFER* Buffer,
        #[in] unsigned long PreferedMaximumLength,
        #[out] unsigned long* CountReturned
        #)
        x = ndrlib.Unpacker(p.StubData)
        DomainHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("DomainHandle %s" % DomainHandle)

        EnumerationContext = x.unpack_long()
        rpclog.debug("EnumerationContext %i" % EnumerationContext)

        UserAccountControl = x.unpack_long()
        rpclog.debug("UserAccountControl %i" % UserAccountControl)

        PreferedMaximumLength = x.unpack_long()
        rpclog.debug("PreferedMaximumLength %i" % PreferedMaximumLength)

        r = ndrlib.Packer()
        r.pack_pointer(EnumerationContext)

        # PSAMPR_ENUMERATION_BUFFER* Buffer
        r.pack_pointer(0x0da260)

        # SAMPR_ENUMERATION_BUFFER Buffer
        s = samr.SAMPR_ENUMERATION_BUFFER(r)
        s.Buffer = ['Administrator','Guest','HelpAssistant','SUPPORT_388945a0']
        s.EntriesRead = len(s.Buffer)
        s.pack()

        # long* CountReturned
        r.pack_long(s.EntriesRead)
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_GetAliasMembership(cls, con, p):
        #3.1.5.9.2 SamrGetAliasMembership (Opnum 16)
        #
        #http://msdn.microsoft.com/en-us/library/cc245816%28v=prot.10%29.aspx
        #
        #long SamrGetAliasMembership(
        #  [in] SAMPR_HANDLE DomainHandle,
        #  [in] PSAMPR_PSID_ARRAY SidArray,
        #  [out] PSAMPR_ULONG_ARRAY Membership
        #);
        x = ndrlib.Unpacker(p.StubData)
        DomainHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("DomainHandle %s" % DomainHandle)

        Count = x.unpack_long()
        # PSAMPR_PSID_ARRAY SidArray
        Pointer = x.unpack_pointer()
        SidArray = samr.SAMPR_PSID_ARRAY(x)

        r = ndrlib.Packer()
        r.pack_long(1)

        # PSAMPR_ULONG_ARRAY Membership
        r.pack_pointer(0x0d15a8)
        r.pack_long(1)
        r.pack_long(514)

        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_LookupNamesInDomain(cls, con, p):
        #3.1.5.11.2 SamrLookupNamesInDomain (Opnum 17)
        #
        #http://msdn.microsoft.com/en-us/library/cc245712%28v=prot.10%29.aspx
        #
        #long SamrLookupNamesInDomain(
        #  [in] SAMPR_HANDLE DomainHandle,
        #  [in, range(0,1000)] unsigned long Count,
        #  [in, size_is(1000), length_is(Count)]
        #    RPC_UNICODE_STRING Names[*],
        #  [out] PSAMPR_ULONG_ARRAY RelativeIds,
        #  [out] PSAMPR_ULONG_ARRAY Use
        #)
        x = ndrlib.Unpacker(p.StubData)
        DomainHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("DomainHandle %s" % DomainHandle)

        # unsigned long Count
        Count= x.unpack_long()
        rpclog.debug("Count %i" % Count)

        # RPC_UNICODE_STRING Names[*]
        Maxcount = x.unpack_long()
        rpclog.debug("Maxcount %i" % Maxcount)
        Offset = x.unpack_long()
        rpclog.debug("Offset %i" % Offset)
        ActualCount = x.unpack_long()
        rpclog.debug("ActualCount %i" % ActualCount)
        Names = samr.RPC_UNICODE_STRING(x,Count)

        global LookupName
        LookupName = Names.Buffer.decode('UTF-16')
        rpclog.debug("LookupName %s" % LookupName)

        r = ndrlib.Packer()

        if LookupName in __userinfo__:
            # PSAMPR_ULONG_ARRAY RelativeIds
            # RelativeIds.Count
            r.pack_long(Count)

            # RelativeIds.Element
            r.pack_pointer(0x0da260)
            r.pack_long(1)

            data = __userinfo__[LookupName]
            rid  = data["RID"]
            r.pack_long(rid)

            # PSAMPR_ULONG_ARRAY Use
            # Use.Count
            r.pack_long(Count)

            # Use.Element
            r.pack_pointer(0x0e1288)
            r.pack_long(1)
            r.pack_long(1)

            # return
            r.pack_long(0)

        else:
            r.pack_long(0)
            r.pack_pointer(0)
            r.pack_long(0)
            r.pack_pointer(0)

            # return
            r.pack_pointer(0xc0000073)

        return r.get_buffer()

    @classmethod
    def handle_OpenUser(cls, con, p):
        #3.1.5.1.9 SamrOpenUser (Opnum 34)
        #
        #http://msdn.microsoft.com/en-us/library/cc245752%28v=prot.10%29.aspx
        #
        #long SamrOpenUser(
        #  [in] SAMPR_HANDLE DomainHandle,
        #  [in] unsigned long DesiredAccess,
        #  [in] unsigned long UserId,
        #  [out] SAMPR_HANDLE* UserHandle
        #);
        x = ndrlib.Unpacker(p.StubData)
        DomainHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("DomainHandle %s" % DomainHandle)

        DesiredAccess = x.unpack_long()
        rpclog.debug("DesiredAccess %i" % DesiredAccess)

        UserId = x.unpack_long()
        rpclog.debug("UserId %i" % UserId)

        r = ndrlib.Packer()
        # UserHandle
        UserHandle = samr.SAMPR_HANDLE(r)
        UserHandle.Handle = b'01234567890123456789'
        UserHandle.pack()

        # return
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_QueryInformationUser(cls, con, p):
        #3.1.5.5.6 SamrQueryInformationUser (Opnum 36)
        #
        #http://msdn.microsoft.com/en-us/library/cc245786%28v=prot.10%29.aspx
        #
        #long SamrQueryInformationUser(
        #  [in] SAMPR_HANDLE UserHandle,
        #  [in] USER_INFORMATION_CLASS UserInformationClass,
        #  [out, switch_is(UserInformationClass)]
        #    PSAMPR_USER_INFO_BUFFER* Buffer
        #);
        x = ndrlib.Unpacker(p.StubData)
        UserHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("UserHandle %s" % UserHandle)

        UserInformationClass = x.unpack_short()
        rpclog.debug("UserInformationClass %i" % UserInformationClass)

        r = ndrlib.Packer()
        #typedef  enum _USER_INFORMATION_CLASS
        #{
        #  UserGeneralInformation = 1,
        #  UserPreferencesInformation = 2,
        #  UserLogonInformation = 3,
        #  UserLogonHoursInformation = 4,
        #  UserAccountInformation = 5,
        #  UserNameInformation = 6,
        #  UserAccountNameInformation = 7,
        #  UserFullNameInformation = 8,
        #  UserPrimaryGroupInformation = 9,
        #  UserHomeInformation = 10,
        #  UserScriptInformation = 11,
        #  UserProfileInformation = 12,
        #  UserAdminCommentInformation = 13,
        #  UserWorkStationsInformation = 14,
        #  UserControlInformation = 16,
        #  UserExpiresInformation = 17,
        #  UserInternal1Information = 18,
        #  UserParametersInformation = 20,
        #  UserAllInformation = 21,
        #  UserInternal4Information = 23,
        #  UserInternal5Information = 24,
        #  UserInternal4InformationNew = 25,
        #  UserInternal5InformationNew = 26
        #} USER_INFORMATION_CLASS,
        # *PUSER_INFORMATION_CLASS;

        # Pointer to the USER_INFORMATION_CLASS
        r.pack_pointer(0x000cc228)

        if UserInformationClass == 21 :
            r.pack_long(UserInformationClass)
            # SAMPR_USER_ALL_INFORMATION
            s = samr.SAMPR_USER_ALL_INFORMATION(r)
            rpclog.debug("LookupName %s" % cls.LookupName)

            if cls.LookupName in __userinfo__:
                data = __userinfo__[cls.LookupName]
                rid  = data["RID"]
                comment = data["comment"]
                s.Buffer = [
                    cls.LookupName,'','','','','',comment,'','','','','','']
                s.UserID = rid
                s.pack()

        # padding
        r.pack_small(0)
        # return
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_GetGroupsForUser (cls, con, p):
        #3.1.5.9.1 SamrGetGroupsForUser (Opnum 39)
        #
        #http://msdn.microsoft.com/en-us/library/cc245815%28v=prot.10%29.aspx
        #
        #long SamrGetGroupsForUser(
        #  [in] SAMPR_HANDLE UserHandle,
        #  [out] PSAMPR_GET_GROUPS_BUFFER* Groups
        #);
        x = ndrlib.Unpacker(p.StubData)
        UserHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("UserHandle %s" % UserHandle)

        # 2.2.3.13 SAMPR_GET_GROUPS_BUFFER
        # http://msdn.microsoft.com/en-us/library/cc245539%28v=prot.10%29.aspx
        #typedef struct _SAMPR_GET_GROUPS_BUFFER {
        #  unsigned long MembershipCount;
        #  [size_is(MembershipCount)] PGROUP_MEMBERSHIP Groups;
        #} SAMPR_GET_GROUPS_BUFFER,
        # *PSAMPR_GET_GROUPS_BUFFER;

        # Note: Information about PGROUP_MEMBERSHIP struct not found on MDSN.
        # The following response is made by refering to Microsoft Network
        # Monitor

        r = ndrlib.Packer()
        r.pack_pointer(0xc6298)

        # MembershipCount;
        r.pack_long(1)

        r.pack_pointer(0xd2a80)
        r.pack_long(1)
        r.pack_long(513)
        r.pack_long(7)

        # return
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_QueryDisplayInformation(cls, con, p):
        #3.1.5.3.3 SamrQueryDisplayInformation (Opnum 40)
        #
        #http://msdn.microsoft.com/en-us/library/cc245763%28PROT.10%29.aspx
        #
        #long SamrQueryDisplayInformation(
        #  [in] SAMPR_HANDLE DomainHandle,
        #  [in] DOMAIN_DISPLAY_INFORMATION DisplayInformationClass,
        #  [in] unsigned long Index,
        #  [in] unsigned long EntryCount,
        #  [in] unsigned long PreferredMaximumLength,
        #  [out] unsigned long* TotalAvailable,
        #  [out] unsigned long* TotalReturned,
        #  [out, switch_is(DisplayInformationClass)]
        #    PSAMPR_DISPLAY_INFO_BUFFER Buffer
        #);
        x = ndrlib.Unpacker(p.StubData)
        DomainHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("DomainHandle %s" % DomainHandle)

        DisplayInformationClass = x.unpack_long()
        rpclog.debug("DisplayInformationClass %i" % DisplayInformationClass)

        Index = x.unpack_long()
        rpclog.debug("Index %i" % Index)

        EntryCount = x.unpack_long()
        rpclog.debug("EntryCount %i" % EntryCount)

        PreferredMaximumLength = x.unpack_long()
        rpclog.debug("PreferredMaximumLength %i" % PreferredMaximumLength)

        r = ndrlib.Packer()
        # unsigned long* TotalAvailable
        r.pack_long(30)
        # unsigned long* TotalReturned
        r.pack_long(30)

        if DisplayInformationClass == 1 :
            r.pack_long(DisplayInformationClass)
            # SAMPR_DOMAIN_DISPLAY_USER_BUFFER
            s = samr.SAMPR_DOMAIN_DISPLAY_USER_BUFFER(r)
            s.Buffer = ['Administrator','Builtin','Full Name','Guest','Builtin','Full Name',
                        'HelpAssistant','Builtin','Full Name','SUPPORT_388945a0','Builtin','Full Name']
            s.EntriesRead = int(len(s.Buffer)/3)
            s.pack()

        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_QueryInformationDomain2(cls, con, p):
        #3.1.5.5.1 SamrQueryInformationDomain2 (Opnum 46)
        #
        #http://msdn.microsoft.com/en-us/library/cc245773%28PROT.13%29.aspx
        #
        #long SamrQueryInformationDomain2(
        #  [in] SAMPR_HANDLE DomainHandle,
        #  [in] DOMAIN_INFORMATION_CLASS DomainInformationClass,
        #  [out, switch_is(DomainInformationClass)]
        #    PSAMPR_DOMAIN_INFO_BUFFER* Buffer
        #)
        x = ndrlib.Unpacker(p.StubData)
        DomainHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("DomainHandle %s" % DomainHandle)

        DisplayInformationClass = x.unpack_long()
        rpclog.debug("DisplayInformationClass %i" % DisplayInformationClass)

        r = ndrlib.Packer()
        #typedef
        #[switch_type(DOMAIN_INFORMATION_CLASS)]
        #  union _SAMPR_DOMAIN_INFO_BUFFER {
        #  [case(DomainPasswordInformation)]
        #    DOMAIN_PASSWORD_INFORMATION Password;
        #  [case(DomainGeneralInformation)]
        #    SAMPR_DOMAIN_GENERAL_INFORMATION General;
        #  [case(DomainLogoffInformation)]
        #    DOMAIN_LOGOFF_INFORMATION Logoff;
        #  [case(DomainOemInformation)]
        #    SAMPR_DOMAIN_OEM_INFORMATION Oem;
        #  [case(DomainNameInformation)]
        #    SAMPR_DOMAIN_NAME_INFORMATION Name;
        #  [case(DomainServerRoleInformation)]
        #    DOMAIN_SERVER_ROLE_INFORMATION Role;
        #  [case(DomainReplicationInformation)]
        #    SAMPR_DOMAIN_REPLICATION_INFORMATION Replication;
        #  [case(DomainModifiedInformation)]
        #    DOMAIN_MODIFIED_INFORMATION Modified;
        #  [case(DomainStateInformation)]
        #    DOMAIN_STATE_INFORMATION State;
        #  [case(DomainGeneralInformation2)]
        #    SAMPR_DOMAIN_GENERAL_INFORMATION2 General2;
        #  [case(DomainLockoutInformation)]
        #    SAMPR_DOMAIN_LOCKOUT_INFORMATION Lockout;
        #  [case(DomainModifiedInformation2)]
        #    DOMAIN_MODIFIED_INFORMATION2 Modified2;
        #} SAMPR_DOMAIN_INFO_BUFFER,
        # *PSAMPR_DOMAIN_INFO_BUFFER;

        # Pointer to the SAMPR_DOMAIN_INFO_BUFFER
        r.pack_pointer(0x23456)

        if DisplayInformationClass == 1:
            # 2.2.4.5 DOMAIN_PASSWORD_INFORMATION
            # http://msdn.microsoft.com/en-us/library/cc245575%28PROT.13%29.aspx
            #typedef struct _DOMAIN_PASSWORD_INFORMATION {
            #  unsigned short MinPasswordLength;
            #  unsigned short PasswordHistoryLength;
            #  unsigned long PasswordProperties;
            #  OLD_LARGE_INTEGER MaxPasswordAge;
            #  OLD_LARGE_INTEGER MinPasswordAge;
            #} DOMAIN_PASSWORD_INFORMATION,
            # *PDOMAIN_PASSWORD_INFORMATION;

            r.pack_long(DisplayInformationClass)
            r.pack_short(0)
            r.pack_short(0)
            r.pack_hyper(999999999999)
            r.pack_hyper(0)

        elif DisplayInformationClass == 8:
            # 2.2.4.8 DOMAIN_MODIFIED_INFORMATION
            # http://msdn.microsoft.com/en-us/library/cc245578%28PROT.10%29.aspx
            #typedef struct _DOMAIN_MODIFIED_INFORMATION {
            #  OLD_LARGE_INTEGER DomainModifiedCount;
            #  OLD_LARGE_INTEGER CreationTime;
            #} DOMAIN_MODIFIED_INFORMATION,
            # *PDOMAIN_MODIFIED_INFORMATION;

            r.pack_long(DisplayInformationClass)
            r.pack_hyper(10)
            # Jun 25,2010 03:40:46.078125000
            r.pack_raw(b'\xc2\x1e\xdc\x23\xd5\x13\xcb\x01')

        elif DisplayInformationClass == 12:
            # 2.2.4.15 SAMPR_DOMAIN_LOCKOUT_INFORMATION
            # http://msdn.microsoft.com/en-us/library/cc245569%28PROT.13%29.aspx
            #typedef struct _SAMPR_DOMAIN_LOCKOUT_INFORMATION {
            #  LARGE_INTEGER LockoutDuration;
            #  LARGE_INTEGER LockoutObservationWindow;
            #  unsigned short LockoutThreshold;
            #} SAMPR_DOMAIN_LOCKOUT_INFORMATION,
            # *PSAMPR_DOMAIN_LOCKOUT_INFORMATION;
            r.pack_long(DisplayInformationClass)
            r.pack_hyper(18446744055709551616) #windows XP give this value
            r.pack_hyper(18446744055709551616)
            r.pack_short(0)

        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_EnumerateAliasesInDomain(cls, con, p):
        #3.1.5.2.4 SamrEnumerateAliasesInDomain (Opnum 15)
        #
        #http://msdn.microsoft.com/en-us/library/cc245758%28PROT.10%29.aspx
        #
        #long SamrEnumerateAliasesInDomain(
        #  [in] SAMPR_HANDLE DomainHandle,
        #  [in, out] unsigned long* EnumerationContext,
        #  [out] PSAMPR_ENUMERATION_BUFFER* Buffer,
        #  [in] unsigned long PreferedMaximumLength,
        #  [out] unsigned long* CountReturned
        #)
        x = ndrlib.Unpacker(p.StubData)
        DomainHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("DomainHandle %s" % DomainHandle)

        EnumerationContext = x.unpack_long()
        rpclog.debug("EnumerationContext %i" % EnumerationContext)

        PreferedMaximumLength = x.unpack_long()
        rpclog.debug("PreferedMaximumLength %i" % PreferedMaximumLength)

        r = ndrlib.Packer()
        r.pack_long(EnumerationContext)

        # PSAMPR_ENUMERATION_BUFFER* Buffer
        r.pack_pointer(0x0da260)

        # SAMPR_ENUMERATION_BUFFER Buffer
        s = samr.SAMPR_ENUMERATION_BUFFER(r)
        s.Buffer = ['Administrator','Guest']
        s.EntriesRead = len(s.Buffer)
        s.pack()

        # long* CountReturned
        r.pack_long(s.EntriesRead)
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_Close(cls, con, p):
        #3.1.5.13.1 SamrCloseHandle (Opnum 1)
        #
        #http://msdn.microsoft.com/en-us/library/cc245722%28v=PROT.13%29.aspx
        #
        #long SamrCloseHandle(
        #[in, out] SAMPR_HANDLE* SamHandle
        #);
        x = ndrlib.Unpacker(p.StubData)
        SamHandle = samr.SAMPR_HANDLE(x)
        rpclog.debug("SamHandle %s" % SamHandle)

        r = ndrlib.Packer()
        s = samr.SAMPR_HANDLE(r)
        s.Handle =  b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
        s.pack()
        r.pack_long(0)

        return r.get_buffer()

class SceSvc(RPCService):
    uuid = UUID('93149ca2-973b-11d1-8c39-00c04fb984f9').hex


class sfcapi(RPCService):
    uuid = UUID('83da7c00-e84f-11d2-9807-00c04f8ec850').hex


class spoolss(RPCService):
    uuid = UUID('12345678-1234-abcd-ef00-0123456789ab').hex

    ops = {
        0x00: "EnumPrinters",
        0x11: "StartDocPrinter",
        0x13: "WritePrinter",
        0x17: "EndDocPrinter",
        0x1d: "ClosePrinter",
        0x45: "OpenPrinter"

    }

    class DOC_INFO_1(object):
        # DOC_INFO_1 Structure
        #
        # http://msdn.microsoft.com/en-us/library/dd162471%28v=VS.85%29.aspx
        #
        #typedef struct _DOC_INFO_1 {
        #  LPTSTR pDocName;
        #  LPTSTR pOutputFile;
        #  LPTSTR pDatatype;
        #} DOC_INFO_1;

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                pass
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Level = self.__packer.unpack_long()
                self.Pointer = self.__packer.unpack_pointer()
                self.pDocName = self.__packer.unpack_pointer()
                self.pOutputFile = self.__packer.unpack_pointer()
                self.pDatatype = self.__packer.unpack_pointer()
                self.DocName = self.__packer.unpack_string()
                self.OutputFile = self.__packer.unpack_string()
                #self.DataType = self.__packer.unpack_string()

#				rpclog.debug("DocName %s OutputFile %s" %(self.DocName,self.OutputFile))

        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                pass

    class PRINTER_INFO_1(object):
        # PRINTER_INFO_1 Structure
        #
        # http://msdn.microsoft.com/en-us/library/dd162844%28v=VS.85%29.aspx
        #
        #typedef struct _PRINTER_INFO_1 {
        #  DWORD  Flags;
        #  LPTSTR pDescription;
        #  LPTSTR pName;
        #  LPTSTR pComment;
        #} PRINTER_INFO_1, *PPRINTER_INFO_1;

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Flags = 0x00018000
                self.Buffer = ''
                self.Buffersize = 0
                self.Offset = 0
            elif isinstance(self.__packer,ndrlib.Unpacker):
                pass
        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                self.__packer.pack_pointer(self.Flags)

                # self.Offset is the distance of the string count from the end
                # of PRINTER_INFO_1 buffer. To count the distance of the string
                # from the start of PRINTER_INFO_1 buffer,
                # self.Buffersize - self offset needed
                for j in range(len(self.Buffer)):
                    count = 0
                    count = len(self.Buffer) - j - 1
                    self.Offset = self.Offset + 2*len(self.Buffer[count])
                    self.__packer.pack_long(self.Buffersize-self.Offset)

                for i in range(len(self.Buffer)):

                    self.__packer.pack_raw(self.Buffer[i].encode('utf16')[2:])
        def size(self):
            size = 4 + 4*len(self.Buffer) + 2* \
                (sum([len(x) for x in self.Buffer]))
            rpclog.debug ("rpclog.debugER_INFO_1 size %i" % size)
            return size

    @classmethod
    def handle_EnumPrinters (cls, con, p):
        #EnumPrinters Function
        #
        #http://msdn.microsoft.com/en-us/library/dd162692%28VS.85%29.aspx
        #
        #BOOL EnumPrinters(
        #  __in   DWORD Flags,
        #  __in   LPTSTR Name,
        #  __in   DWORD Level,
        #  __out  LPBYTE pPrinterEnum,
        #  __in   DWORD cbBuf,
        #  __out  LPDWORD pcbNeeded,
        #  __out  LPDWORD pcReturned
        #);

        p = ndrlib.Unpacker(p.StubData)
        Flags = p.unpack_long()
        Name = p.unpack_pointer()
        Level = p.unpack_long()
        Pointer = p.unpack_pointer()
        cbBuf = p.unpack_long()

        rpclog.debug("Flags %s Name %s Level %i cbBuf %i " %
                     (Flags, Name, Level, cbBuf))

        r = ndrlib.Packer()
        # Pointer to PRINTER_INFO_X buffer
        r.pack_pointer(0x6b254)

        # PRINTER_INFO_1 Buffer
        a = spoolss.PRINTER_INFO_1(r)

        # these string are the default response of windows xp
        # 'Windows NT Remote Printers' need for msf fingerprinting OS language as 'English version'
        # https://www.metasploit.com/redmine/projects/framework/repository/revisions/8941/entry/lib/msf/core/exploit/smb.rb#L396

        a.Buffer = ['Internet URL Printers\0','Windows NT Internet Provider\0','Windows NT Internet Printing\0','Remote Printers\0','Windows NT Remote Printers\0',
                    'Microsoft Windows Network\0','Locally Connected Printers\0','Windows NT Local Print Providor\0','Windows NT Local Printers\0']
        a.Buffersize = a.size()

        if Level == 1 and cbBuf != 0:
            r.pack_long(a.Buffersize)
            a.pack()

            r.pack_long(a.Buffersize)
            r.pack_long(3) #pcReturned, default in windows xp is 3
            r.pack_long(0)
        else:
            # this need to trick metasploit ms08-067 exploit
            # dionaea need send a malformed response if the cbBuf == 0
            r.pack_long(0)
            r.pack_long(a.Buffersize)
            r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_OpenPrinter(cls, con, p):
        #OpenPrinter Function
        #
        #http://msdn.microsoft.com/en-us/library/dd162751%28v=VS.85%29.aspx
        #
        #BOOL OpenPrinter(
        #  __in   LPTSTR pPrinterName,
        #  __out  LPHANDLE phPrinter,
        #  __in   LPPRINTER_DEFAULTS pDefault
        #);

        x = ndrlib.Unpacker(p.StubData)
        pPrinterName = x.unpack_pointer()
        PrinterName = x.unpack_string()
        print("PrinterName %s" % PrinterName)

        pDatatype = x.unpack_pointer()
        print("Datatype %s" % pDatatype)

        cbBuf = x.unpack_long()
        pDevMode = x.unpack_pointer()
        print("DevMode %s" % pDevMode)

        DesiredAccess = x.unpack_long()
        print("DesiredAccess %x" % DesiredAccess)

        #Below is the ClientInfo structure which showed in
        #Microsoft Network Monitor, but I cant find the correct doc to refer
        Level = x.unpack_long()
        SwitchValue = x.unpack_long()
        Pointer = x.unpack_pointer()
        Size = x.unpack_long()
        Buff = x.unpack_raw(Size)

        print("Size %i Buff %s" % (Size, Buff))

        r = ndrlib.Packer()
        # Returned Handle
        r.pack_raw(b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0')
        # Success
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_ClosePrinter(cls, con, p):
        r = ndrlib.Packer()
        r.pack_long(0)
        return r.get_buffer()


    @classmethod
    def handle_StartDocPrinter(cls, con, p):
        #StartDocPrinter Function
        #
        #http://msdn.microsoft.com/en-us/library/dd145115%28v=VS.85%29.aspx
        #
        #DWORD StartDocPrinter(
        #  __in  HANDLE hPrinter,
        #  __in  DWORD Level,
        #  __in  LPBYTE pDocInfo
        #);

        x = ndrlib.Unpacker(p.StubData)
        hPrinter = x.unpack_raw(20)
        rpclog.debug("hPrinter %s" % hPrinter)

        Level = x.unpack_long()
        rpclog.debug("Level %i" % Level)

        DocInfo = spoolss.DOC_INFO_1(x)
        DocName = DocInfo.DocName.decode('UTF-16')[:-1]
        OutputFile = DocInfo.OutputFile.decode('UTF-16')[:-1]

        rpclog.debug("docname {} outputfile {}".format(DocName, OutputFile))

        if OutputFile.startswith('\\\\') and OutputFile.endswith('\\PIPE\\ATSVC'):
            # FIXME PIPE ATSVC COMMAND
            pass
        else:
            i = incident("dionaea.download.offer")
            i.con = con
            i.url = "spoolss://" + con.remote.host + '/' + OutputFile
            i.report()


        r = ndrlib.Packer()
        # Job ID
        r.pack_long(3)
        # Success
        r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_EndDocPrinter(cls, con, p):
        r=ndrlib.Packer()
        r.pack_long(0)
        return r.get_buffer()

    @classmethod
    def handle_WritePrinter(cls, con, p):
        #WritePrinter Function
        #
        #http://msdn.microsoft.com/en-us/library/dd145226%28v=VS.85%29.aspx
        #
        #BOOL WritePrinter(
        #  __in   HANDLE hPrinter,
        #  __in   LPVOID pBuf,
        #  __in   DWORD cbBuf,
        #  __out  LPDWORD pcWritten
        #);



        # For MS10-061 SPOOLSS exploit with metasploit,
        # the payload has sent in packet fragment.
        # The packet dissection for the first and middle fragment is different, here the trick needed to make it work.
        # Meaning of PacketFlags in dcerpc header:
        # 0x00 : Middle fragment
        # 0x01 : First fragment
        # 0x02 : Last fragment
        # 0x03 : No fragment needed
        #
        # FIXME actually this defragmentation should be in
        # smbd.process_dcerpc_packet

        if p.PacketFlags == 0:
            con.printer += p.StubData
            return None
        elif p.PacketFlags == 1:
            con.printer += p.StubData
            return None
        elif p.PacketFlags == 2:
            con.printer += p.StubData
            x = ndrlib.Unpacker(con.printer)
            hPrinter = x.unpack_raw(20)
            cbBuf = x.unpack_long()
            Buf = x.unpack_raw(cbBuf)

            dionaea_config = g_dionaea.config().get("dionaea")
            download_dir = dionaea_config.get("download.dir")
            download_suffix = dionaea_config.get("download.suffix", ".tmp")
            x = tempfile.NamedTemporaryFile(
                delete=False,
                prefix="spoolss-",
                suffix=download_suffix,
                dir=download_dir
            )
            x.write(Buf)
            x.close()

            i = incident("dionaea.download.complete")
            i.path = x.name
            i.url = "spoolss://" + con.remote.host
            i.con = con
            i.report()

            r = ndrlib.Packer()
            r.pack_long(len(Buf))
            r.pack_long(0)
            return r.get_buffer()

        elif p.PacketFlags == 3:
            x = ndrlib.Unpacker(p.StubData)
            hPrinter = x.unpack_raw(20)
            cbBuf = x.unpack_long()

            r = ndrlib.Packer()
            r.pack_long(cbBuf)
            r.pack_long(0)
            return r.get_buffer()





STYPE_DISKTREE = 0x00000000 # Disk drive
STYPE_PRINTQ   = 0x00000001 # Print queue
STYPE_DEVICE   = 0x00000002 # Communication device
STYPE_IPC      = 0x00000003 # Interprocess communication (IPC)
STYPE_SPECIAL  = 0x80000000 # Special share reserved for interprocess
# communication (IPC$) or remote administration of the server (ADMIN$).
# Can also refer to administrative shares such as C$, D$, E$, and so forth.
STYPE_TEMPORARY= 0x40000000 # A temporary share that is not persisted
# for creation each time the file server initializes.

# Overwritten by smb config
__shares__ = {}


class SRVSVC(RPCService):
    """ [MS-SRVS]: Server Service Remote Protocol Specification

    http://msdn.microsoft.com/en-us/library/cc247080%28v=PROT.13%29.aspx

    http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-SRVS%5D.pdf

    """
    uuid = UUID('4b324fc8-1670-01d3-1278-5a47bf6ee188').hex
    version_major = 0
    version_minor = 0

    ops = {
        0x0e: "NetShareAdd",
        0x0f: "NetShareEnum",
        0x10: "NetrShareGetInfo",
        0x15: "NetServerGetInfo",
        0x1c: "NetrRemoteTOD",
        0x1f: "NetPathCanonicalize",
        0x20: "NetPathCompare",
        0x22: "NetNameCanonicalize"
    }
    vulns  = {
        0x1f: "MS08-67",
        0x20: "MS08-67",
    }

    class SRVSVC_HANDLE(object):
        # 2.2.1.1 SRVSVC_HANDLE
        #
        # http://msdn.microsoft.com/en-us/library/cc247105%28PROT.10%29.aspx
        #
        # 	typedef [handle, string] WCHAR* SRVSVC_HANDLE;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Handle = b''
                self.Pointer = 0x3a20f2
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Ref = self.__packer.unpack_pointer()
                self.Handle = self.__packer.unpack_string()
        def pack(self):
            if isinstance(self.__packer, ndrlib.Packer):
                self.__packer.pack_pointer(self.Pointer)
                self.__packer.pack_string(self.Handle)

    class SHARE_INFO_0_CONTAINER(object):
        # 2.2.4.32 SHARE_INFO_0_CONTAINER
        #
        # http://msdn.microsoft.com/en-us/library/cc247156%28PROT.13%29.aspx
        #
        #typedef struct _SHARE_INFO_0_CONTAINER {
        #  DWORD EntriesRead;
        #  [size_is(EntriesRead)] LPSHARE_INFO_0 Buffer;
        #} SHARE_INFO_0_CONTAINER;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.EntriesRead = 0
                self.Data = []
                self.Pointer = 0x23456
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Ptr = self.__packer.unpack_pointer()
                self.EntriesRead = self.__packer.unpack_long()
                self.Buffer = self.__packer.unpack_pointer()
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                # EntriesRead
                self.EntriesRead = len(self.Data)
                self.__packer.pack_long(self.EntriesRead)
                # LPSHARE_INFO_0 Buffer
                b = SRVSVC.SHARE_INFO_0(self.__packer)
                b.Data = self.Data
                b.MaxCount = self.EntriesRead
                b.pack()


    class SHARE_INFO_1_CONTAINER(object):
        # 2.2.4.33 SHARE_INFO_1_CONTAINER
        #
        # http://msdn.microsoft.com/en-us/library/cc247157%28PROT.10%29.aspx
        #
        # typedef struct _SHARE_INFO_1_CONTAINER {
        #   DWORD EntriesRead;
        #   [size_is(EntriesRead)] LPSHARE_INFO_1 Buffer;
        # } SHARE_INFO_1_CONTAINER;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.EntriesRead = 0
                self.Data = {}
                self.Pointer = 0x23456
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Ptr = self.__packer.unpack_pointer()
                self.EntriesRead = self.__packer.unpack_long()
                self.Buffer = self.__packer.unpack_pointer()
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                # EntriesRead
                self.EntriesRead = len(self.Data)
                self.__packer.pack_long(self.EntriesRead)
                # LPSHARE_INFO_1 Buffer
                b = SRVSVC.SHARE_INFO_1(self.__packer)
                b.Data = self.Data
                b.pack()


    class SHARE_INFO_2_CONTAINER(object):
        # 2.2.4.34 SHARE_INFO_2_CONTAINER
        #
        # http://msdn.microsoft.com/en-us/library/cc247158%28PROT.13%29.aspx
        #
        #typedef struct _SHARE_INFO_2_CONTAINER {
        #  DWORD EntriesRead;
        #  [size_is(EntriesRead)] LPSHARE_INFO_2 Buffer;
        #} SHARE_INFO_2_CONTAINER,
        # *PSHARE_INFO_2_CONTAINER,
        # *LPSHARE_INFO_2_CONTAINER;
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.EntriesRead = 0
                self.Data = {}
                self.Pointer = 0x23456
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Ptr = self.__packer.unpack_pointer()
                self.EntriesRead = self.__packer.unpack_long()
                self.Buffer = self.__packer.unpack_pointer()
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.EntriesRead = len(self.Data)
#				self.__packer.pack_long(self.EntriesRead)
                # LPSHARE_INFO_2 Buffer
                b = SRVSVC.SHARE_INFO_2(self.__packer)
                b.Data = self.Data
                b.pack()

    class SHARE_INFO_502_CONTAINER(object):
        # 2.2.4.36 SHARE_INFO_502_CONTAINER
        #
        # http://msdn.microsoft.com/en-us/library/cc247160%28PROT.13%29.aspx
        #
        # typedef struct _SHARE_INFO_502_CONTAINER {
        #   DWORD EntriesRead;
        #   [size_is(EntriesRead)] LPSHARE_INFO_502_I Buffer;
        # } SHARE_INFO_502_CONTAINER,
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.EntriesRead = 0
                self.Data = {}
                self.Pointer = 0x23456
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.Ctr = self.__packer.unpack_pointer()
                self.Ptr = self.__packer.unpack_pointer()
                self.EntriesRead = self.__packer.unpack_long()
                self.Buffer = self.__packer.unpack_pointer()
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.EntriesRead = len(self.Data)
                self.__packer.pack_long(self.EntriesRead)
                # SHARE_INFO_502_I Buffer
                b = SRVSVC.SHARE_INFO_502(self.__packer)
                b.Data = self.Data
                b.pack()

    class SHARE_INFO_0(object):
        # 2.2.4.22 SHARE_INFO_0
        #
        # http://msdn.microsoft.com/en-us/library/cc247146%28v=PROT.13%29.aspx
        #
        #typedef struct _SHARE_INFO_0 {
        #  [string] wchar_t* shi0_netname;
        #} SHARE_INFO_0,
        # *PSHARE_INFO_0,
        # *LPSHARE_INFO_0
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Data = {}
                self.Pointer = 0x99999
                self.MaxCount = 0
                self.Netname_pointer = 0x34567
            elif isinstance(self.__packer,ndrlib.Unpacker):
                pass
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_pointer(self.Pointer)
                # MaxCount, needed as the NDR array
                self.MaxCount = len(self.Data)
                self.__packer.pack_long(self.MaxCount)

                for i in range(self.MaxCount):
                    self.__packer.pack_pointer(self.Netname_pointer) # netname
                for j in self.Data:
                    data = self.Data[j]
                    self.__packer.pack_string_fix(
                        str(j+'\0').encode('utf16')[2:])


    class SHARE_INFO_1(object):
        # 2.2.4.23 SHARE_INFO_1
        #
        # http://msdn.microsoft.com/en-us/library/cc247147%28PROT.10%29.aspx
        #
        # typedef struct _SHARE_INFO_1 {
        #   [string] wchar_t* shi1_netname;
        #   DWORD shi1_type;
        #   [string] wchar_t* shi1_remark;
        # } SHARE_INFO_1,
        #  *PSHARE_INFO_1,
        #  *LPSHARE_INFO_1;

        # http://msdn.microsoft.com/en-us/library/cc247150%28PROT.10%29.aspx

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Data = {}
                self.Pointer = 0x99999
                self.MaxCount = 0
                self.Netname_pointer = 0x34567
                self.Type = 0x00000000 # STYPE_DISKTREE
                self.Remark_pointer = 0x45678
            elif isinstance(self.__packer,ndrlib.Unpacker):
                pass
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_pointer(self.Pointer)
                # MaxCount, needed as the NDR array
                self.MaxCount = len(self.Data)
                self.__packer.pack_long(self.MaxCount)

                for i in self.Data:
                    data = self.Data[i]
                    self.__packer.pack_pointer(self.Netname_pointer) # netname
                    self.__packer.pack_long(data['type']) # type
                    self.__packer.pack_pointer(self.Remark_pointer) # remark

                for j in self.Data:
                    data = self.Data[j]
                    self.__packer.pack_string_fix(
                        str(j+'\0').encode('utf16')[2:])
                    self.__packer.pack_string_fix(
                        str(data['comment']+'\0').encode('utf16')[2:])

    class SHARE_INFO_502(object):
        # 2.2.4.26 SHARE_INFO_502_I
        #
        # http://msdn.microsoft.com/en-us/library/cc247150%28v=PROT.13%29.aspx
        #
        # typedef struct _SHARE_INFO_502_I {
        #  [string] WCHAR* shi502_netname;
        #  DWORD shi502_type;
        #  [string] WCHAR* shi502_remark;
        #  DWORD shi502_permissions;
        #  DWORD shi502_max_uses;
        #  DWORD shi502_current_uses;
        #  [string] WCHAR* shi502_path;
        #  [string] WCHAR* shi502_passwd;
        #  DWORD shi502_reserved;
        #  [size_is(shi502_reserved)] unsigned char* shi502_security_descriptor;
        #} SHARE_INFO_502_I,
        # *PSHARE_INFO_502_I,
        # *LPSHARE_INFO_502_I;
        def __init__(self, p, data=None):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Data = []
                self.Pointer = 0x99999
                self.MaxCount = 0
                self.Netname_pointer = 0x34567
                self.Type = 0x00000000
                self.Remark_pointer = 0x45678
                self.Permissions = 0
                self.Max_uses = 0xffffffff
                self.Current_uses = 1
                self.Path_pointer = 0x87654
                self.Passwd_pointer = 0
                self.Reserved = 0
                self.Security_descriptor = 0
            elif isinstance(self.__packer,ndrlib.Unpacker):
                pass
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_pointer(self.Pointer)

                self.MaxCount = len(self.Data)
                self.__packer.pack_long(self.MaxCount)

                for i in self.Data:
                    data = self.Data[i]
                    self.__packer.pack_pointer(self.Netname_pointer) # netname
                    self.__packer.pack_long(data['type']) # STYPE_DISKTREE
                    self.__packer.pack_pointer(self.Remark_pointer) # remark
                    self.__packer.pack_long(self.Permissions)		# permissions
                    self.__packer.pack_long(self.Max_uses) # max_uses
                    self.__packer.pack_long(self.Current_uses)		# current_uses
                    self.__packer.pack_pointer(self.Path_pointer) # path
                    self.__packer.pack_pointer(self.Passwd_pointer) 	# passwd
                    self.__packer.pack_long(self.Reserved) # reserved
                    # security descriptor
                    self.__packer.pack_pointer(self.Security_descriptor)

                for j in self.Data:
                    data = self.Data[i]
                    self.__packer.pack_string_fix(
                        str(j+'\0').encode('utf16')[2:])
                    self.__packer.pack_string_fix(
                        str(data['path']+'\0').encode('utf16')[2:])
                    self.__packer.pack_string_fix(
                        str(data['comment']+'\0').encode('utf16')[2:])

    class SHARE_INFO_2(object):
        #2.2.4.24 SHARE_INFO_2
        #
        #http://msdn.microsoft.com/en-us/library/cc247148%28v=PROT.13%29.aspx
        #
        #typedef struct _SHARE_INFO_2 {
        #  [string] wchar_t* shi2_netname;
        #  DWORD shi2_type;
        #  [string] wchar_t* shi2_remark;
        #  DWORD shi2_permissions;
        #  DWORD shi2_max_uses;
        #  DWORD shi2_current_uses;
        #  [string] wchar_t* shi2_path;
        #  [string] wchar_t* shi2_passwd;
        #} SHARE_INFO_2
        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Data = {}
                self.Pointer = 0x99999
                self.MaxCount = 0
                self.Netname_pointer = 0x34567
                self.Type = 0x00000000
                self.Remark_pointer = 0x45678
                self.Permissions = 0
                self.Max_uses = 0xffffffff
                self.Current_uses = 1
                self.Path_pointer = 0x6789
                self.Passwd_pointer = 0x56789
            elif isinstance(self.__packer,ndrlib.Unpacker):
                self.ref = self.__packer.unpack_pointer()
                self.netname = self.__packer.unpack_pointer()
                self.sharetype = self.__packer.unpack_long()
                self.remark = self.__packer.unpack_long()
                self.permission = self.__packer.unpack_long()
                self.max_use = self.__packer.unpack_long()
                self.current_use = self.__packer.unpack_long()
                self.path = self.__packer.unpack_pointer()
                self.passwd = self.__packer.unpack_pointer()
                self.share_name = self.__packer.unpack_string()
                self.share_comment = self.__packer.unpack_string()
                self.share_path = self.__packer.unpack_string()
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                #				self.__packer.pack_pointer(self.Pointer)
                #				self.MaxCount = len(self.Data)
                #				self.__packer.pack_long(self.MaxCount)

                rpclog.warn("%s" % self.Data)
#				raise Exception()

                for i in self.Data:
                    data = self.Data[i]
                    self.__packer.pack_pointer(self.Netname_pointer) # netname
                    self.__packer.pack_long(data['type']) # STYPE_DISKTREE
                    self.__packer.pack_pointer(self.Remark_pointer) # remark
                    self.__packer.pack_long(self.Permissions) # permissions
                    self.__packer.pack_long(self.Max_uses) # max_uses
                    self.__packer.pack_long(self.Current_uses) # current_uses
                    self.__packer.pack_pointer(self.Path_pointer) # path
                    self.__packer.pack_pointer(self.Passwd_pointer) # passwd

                for j in self.Data:
                    data = self.Data[j]
                    # NetName
                    self.__packer.pack_string_fix(
                        str(j+'\0').encode('utf16')[2:])
                    # Remark
                    self.__packer.pack_string_fix(
                        str(data['comment']+'\0').encode('utf16')[2:])
                    # Path
                    self.__packer.pack_string_fix(
                        str(data['path']+'\0').encode('utf16')[2:])
                    # Password
		    # this is necessary for Metasploit module /exploit/linux/samba/is_known_pipename
                    self.__packer.pack_string_fix(
                        str('\0').encode('utf16')[2:])


    class SERVER_INFO_101(object):
        # 2.2.4.41 SERVER_INFO_101
        #
        # http://msdn.microsoft.com/en-us/library/cc247164%28v=PROT.13%29.aspx
        #
        #typedef struct _SERVER_INFO_101 {
        #  DWORD sv101_platform_id;
        #  [string] wchar_t* sv101_name;
        #  DWORD sv101_version_major;
        #  DWORD sv101_version_minor;
        #  DWORD sv101_type;
        #  [string] wchar_t* sv101_comment;
        #} SERVER_INFO_101,
        # *PSERVER_INFO_101,
        # *LPSERVER_INFO_101;

        def __init__(self, p):
            self.__packer = p
            if isinstance(self.__packer,ndrlib.Packer):
                self.Data = {}
                self.Pointer = 0x99999
                # Windows NT or a newer Windows operating system version.
                self.Platform_id = 500
                self.Name_pointer= 0x68458
                self.Comment_pointer = 0x73429
                self.Version_major = 5 # Windows XP SP2 default reply
                self.Version_minor = 1 # Windows XP SP2 default reply
                # self.Type = 0x00051003 # Windows XP SP2 default reply (Type:
                # Workstation, Server, NT Workstation, Potential Browser,
                # Master Browser)
                self.Type = 0xFFFFFFFF # All servers
            elif isinstance(self.__packer,ndrlib.Unpacker):
                pass
        def pack(self):
            if isinstance(self.__packer,ndrlib.Packer):
                self.__packer.pack_pointer(self.Pointer)
                self.__packer.pack_long(self.Platform_id)
                self.__packer.pack_pointer(self.Name_pointer)
                self.__packer.pack_long(self.Version_major)
                self.__packer.pack_long(self.Version_minor)
                self.__packer.pack_long(self.Type)
                self.__packer.pack_pointer(self.Comment_pointer)

                for j in range(len(self.Data)):
                    self.__packer.pack_string_fix(
                        self.Data[j].encode('utf16')[2:])


    @classmethod
    def handle_NetShareEnum(cls, con, p):

        x = ndrlib.Unpacker(p.StubData)

        # 3.1.4.8 NetrShareEnum (Opnum 15)
        #
        # http://msdn.microsoft.com/en-us/library/cc247276%28PROT.10%29.aspx
        #
        #	NET_API_STATUS NetrShareEnum(
        #	  [in, string, unique] SRVSVC_HANDLE ServerName,
        #	  [in, out] LPSHARE_ENUM_STRUCT InfoStruct,
        #	  [in] DWORD PreferedMaximumLength,
        #	  [out] DWORD* TotalEntries,
        #	  [in, out, unique] DWORD* ResumeHandle
        #	);

        ServerName = SRVSVC.SRVSVC_HANDLE(x)

        # 2.2.4.38 SHARE_ENUM_STRUCT
        #
        # http://msdn.microsoft.com/en-us/library/cc247161%28PROT.10%29.aspx
        #
        #	typedef struct _SHARE_ENUM_STRUCT {
        #	  DWORD Level;
        #	  [switch_is(Level)] SHARE_ENUM_UNION ShareInfo;
        #	} SHARE_ENUM_STRUCT,
        #	 *PSHARE_ENUM_STRUCT,
        #	 *LPSHARE_ENUM_STRUCT;

        infostruct_level = x.unpack_long()
        infostruct_share = x.unpack_long()

        # typedef
        # [switch_type(DWORD)]
        #   union _SHARE_ENUM_UNION {
        #   [case(0)]
        # 	SHARE_INFO_0_CONTAINER* Level0;
        #   [case(1)]
        # 	SHARE_INFO_1_CONTAINER* Level1;
        #   [case(2)]
        # 	SHARE_INFO_2_CONTAINER* Level2;
        #   [case(501)]
        # 	SHARE_INFO_501_CONTAINER* Level501;
        #   [case(502)]
        # 	SHARE_INFO_502_CONTAINER* Level502;
        #   [case(503)]
        # 	SHARE_INFO_503_CONTAINER* Level503;
        # } SHARE_ENUM_UNION;
        if infostruct_share == 0:
            buffer = SRVSVC.SHARE_INFO_0_CONTAINER(x)
        elif infostruct_share == 1:
            buffer = SRVSVC.SHARE_INFO_1_CONTAINER(x)
        elif infostruct_share == 502:
            buffer = SRVSVC.SHARE_INFO_502_CONTAINER(x)

        preferdmaxlen = x.unpack_long()

        # ResumeHandle
        resumehandleptr = x.unpack_pointer()
        resumehandle = 0
        if resumehandleptr != 0:
            resumehandle = x.unpack_long()

        rpclog.debug("infostruct_share %i preferdmaxlen %i  resumehandleptr %x resumehandle %i" % (
            infostruct_share,preferdmaxlen,resumehandleptr,resumehandle) )

        # compile reply
        r = ndrlib.Packer()
        r.pack_long(infostruct_level)
        r.pack_long(infostruct_share)

        # pointer to the SHARE_INFO_X_CONTAINER
        r.pack_pointer(0x23456)

        if infostruct_share == 0:
            s = SRVSVC.SHARE_INFO_0_CONTAINER(r)
        elif infostruct_share == 1:
            s = SRVSVC.SHARE_INFO_1_CONTAINER(r)
        elif infostruct_share == 502:
            s = SRVSVC.SHARE_INFO_502_CONTAINER(r)

        s.Data = __shares__
        s.pack()

        # total entries
        r.pack_long(s.EntriesRead)

        # resume handle
        r.pack_pointer(0x47123123)
        r.pack_long(0)

        r.pack_long(0)
        return r.get_buffer()

    @classmethod
    def handle_NetPathCanonicalize(cls, con, p):
        # MS08-067
        #	WERROR srvsvc_NetPathCanonicalize(
        #		[in,unique]   [string,charset(UTF16)] uint16 *server_unc,
        #		[in]   [string,charset(UTF16)] uint16 path[],
        #		[out]  [size_is(maxbuf)] uint8 can_path[],
        #		[in]   uint32 maxbuf,
        #		[in]   [string,charset(UTF16)] uint16 prefix[],
        #		[in,out,ref] uint32 *pathtype,
        #		[in]    uint32 pathflags
        #		);
        x = ndrlib.Unpacker(p.StubData)
        ref        = x.unpack_pointer()
        server_unc = x.unpack_string()
        path       = x.unpack_string()
        maxbuf     = x.unpack_long()
        prefix     = x.unpack_string()
        pathtype   = x.unpack_long()
        pathflags  = x.unpack_long()
        rpclog.debug("ref 0x%x server_unc %s path %s maxbuf %s prefix %s pathtype %i pathflags %i" % (
            ref, server_unc, path, maxbuf, prefix, pathtype, pathflags))

        # conficker is stubborn
        # dionaea replies to the exploit, conficker retries to exploit
        # I'd prefer a real check for a bad path, but the path provided by conficker is not utf16,
        # therefore it is not possible to canonicalize the path and check if it path canonicalizes beyond /
        # the workaround ... is checking for a 'long' path ...
        if len(path) > 128:
            raise DCERPCValueError("path","too long", path)

        r = ndrlib.Packer()
        r.pack_long(pathtype)
        r.pack_long(0)
        r.pack_string(path)


        return r.get_buffer()

    @classmethod
    def handle_NetPathCompare(cls, con, p):
        # MS08-067
        #	WERROR srvsvc_NetPathCompare(
        #		[in,unique]   [string,charset(UTF16)] uint16 *server_unc,
        #		[in]   [string,charset(UTF16)] uint16 path1[],
        #		[in]   [string,charset(UTF16)] uint16 path2[],
        #		[in]    uint32 pathtype,
        #		[in]    uint32 pathflags
        #		);
        p = ndrlib.Unpacker(p.StubData)
        ref        = p.unpack_pointer()
        server_unc = p.unpack_string()
        path1       = p.unpack_string()
        path2     = p.unpack_string()
        pathtype   = p.unpack_long()
        pathflags  = p.unpack_long()
        rpclog.debug("ref 0x%x server_unc %s path1 %s path2 %s pathtype %i pathflags %i" % (
            ref, server_unc, path1, path2, pathtype, pathflags))
        r = ndrlib.Packer()
        x = (path1 > path2) - (path1 < path2)
        if x < 0:
            r.pack_long( 0 )
        else:
            r.pack_long( 0 )
#		r.pack_long( x )
        return r.get_buffer()

    @classmethod
    def handle_NetShareAdd(cls, con, p):
        #3.1.4.7 NetrShareAdd (Opnum 14)
        #
        #http://msdn.microsoft.com/en-us/library/cc247275%28v=PROT.10%29.aspx
        #
        #NET_API_STATUS NetrShareAdd(
        #[in, string, unique] SRVSVC_HANDLE ServerName,
        #  [in] DWORD Level,
        #  [in, switch_is(Level)] LPSHARE_INFO InfoStruct,
        #  [in, out, unique] DWORD* ParmErr
        #);
        p = ndrlib.Unpacker(p.StubData)
        ServerName = SRVSVC.SRVSVC_HANDLE(p)
        infostruct_level = p.unpack_long()
        infostruct_share = p.unpack_long()

        if infostruct_share == 2:
            buffer = SRVSVC.SHARE_INFO_2(p)

        ptr_parm = p.unpack_pointer()
        error = p.unpack_long()

        rpclog.debug("infostruct_share %i ptr_parm %x ParmErr %i" %
                     (infostruct_share,ptr_parm,error) )

        r = ndrlib.Packer()
        r.pack_pointer(0x324567)
        r.pack_long(0)
        r.pack_long(0)
        return r.get_buffer()

    @classmethod
    def handle_NetrShareGetInfo(cls, con, p):
        #3.1.4.10 NetrShareGetInfo (Opnum 16)
        #
        #http://msdn.microsoft.com/en-us/library/cc247236%28PROT.13%29.aspx
        #
        #NET_API_STATUS NetrShareGetInfo(
        #  [in, string, unique] SRVSVC_HANDLE ServerName,
        #  [in, string] WCHAR* NetName,
        #  [in] DWORD Level,
        #  [out, switch_is(Level)] LPSHARE_INFO InfoStruct
        #);
        p = ndrlib.Unpacker(p.StubData)
        ServerName = SRVSVC.SRVSVC_HANDLE(p)
        NetName = p.unpack_string()
        Level = p.unpack_long()
        rpclog.debug("NetName %s Level %i" % (NetName,Level))

        r = ndrlib.Packer()
        r.pack_long(Level)

        # pointer to the SHARE_INFO_X_CONTAINER
        r.pack_pointer(0x23456)

        if Level == 2:
            s = SRVSVC.SHARE_INFO_2_CONTAINER(r)
            NetName = NetName.decode('UTF-16')[:-1]

            if NetName in __shares__:
                data = __shares__[NetName]
                s.Data = {NetName:data}
            else:
                rpclog.warn(
                    "FIXME: this code has to be written, lame workaround for now")
                data = __shares__['C$']
                s.Data = {NetName:data}
            s.pack()

        r.pack_long(0)
        return r.get_buffer()

    @classmethod
    def handle_NetNameCanonicalize (cls, con, p):
        #3.1.4.33 NetprNameCanonicalize (Opnum 34)
        #
        #http://msdn.microsoft.com/en-us/library/cc247261%28PROT.13%29.aspx
        #
        #NET_API_STATUS NetprNameCanonicalize(
        #  [in, string, unique] SRVSVC_HANDLE ServerName,
        #  [in, string] WCHAR* Name,
        #  [out, size_is(OutbufLen)] WCHAR* Outbuf,
        #  [in, range(0,64000)] DWORD OutbufLen,
        #  [in] DWORD NameType,
        #  [in] DWORD Flags
        #);

        p = ndrlib.Unpacker(p.StubData)
        ServerName = SRVSVC.SRVSVC_HANDLE(p)
        Name = p.unpack_string()
        Outbuflen = p.unpack_long()
        NameType = p.unpack_long()
        Flags = p.unpack_long()
        rpclog.debug("ServerName %s Name %s Outbuflen %i Nametype %i Flags %i" % (
            ServerName, Name, Outbuflen , NameType, Flags))

        r = ndrlib.Packer()

        # Metasploit smb fingerprinting for OS type
        # https://www.metasploit.com/redmine/projects/framework/repository/revisions/8941/entry/lib/msf/core/exploit/smb.rb#L324

        # for 'Windows XP Service Pack 0 / 1'
        if OS_TYPE == 1:
            r.pack_pointer(0)
            r.pack_string(Name)
            r.pack_long(0)

        # for 'Windows XP Service Pack 2+'
        if OS_TYPE == 2 or OS_TYPE == 3:
            r.pack_pointer(0x000006f7)
            r.pack_long(0)

        return r.get_buffer()

    @classmethod
    def handle_NetrRemoteTOD(cls, con, p):
        #3.1.4.21 NetrRemoteTOD (Opnum 28)
        #
        #http://msdn.microsoft.com/en-us/library/cc247248%28v=PROT.13%29.aspx
        #
        #NET_API_STATUS NetrRemoteTOD(
        #  [in, string, unique] SRVSVC_HANDLE ServerName,
        #  [out] LPTIME_OF_DAY_INFO* BufferPtr
        #);
        p = ndrlib.Unpacker(p.StubData)
        ServerName = SRVSVC.SRVSVC_HANDLE(p)

        r = ndrlib.Packer()

        # pointer to the LPTIME_OF_DAY_INFO* BufferPtr
        # Metasploit smb fingerprinting for OS type
        # for 'Windows XP Service Pack 3'
        if OS_TYPE == 3:
            r.pack_pointer(0x00020000)
        else :
            r.pack_pointer(0x23456)

        #typedef struct TIME_OF_DAY_INFO {
        #  DWORD tod_elapsedt;
        #  DWORD tod_msecs;
        #  DWORD tod_hours;
        #  DWORD tod_mins;
        #  DWORD tod_secs;
        #  DWORD tod_hunds;
        #  long tod_timezone;
        #  DWORD tod_tinterval;
        #  DWORD tod_day;
        #  DWORD tod_month;
        #  DWORD tod_year;
        #  DWORD tod_weekday;
        #} TIME_OF_DAY_INFO,
        # *PTIME_OF_DAY_INFO,
        # *LPTIME_OF_DAY_INFO;

        ctime = localtime()
        #Eg, time.struct_time(tm_year=2010, tm_mon=7, tm_mday=13, tm_hour=2, tm_min=12, tm_sec=27, tm_wday=1, tm_yday=194, tm_isdst=0)

        r.pack_long(int(time()))#elapsedt
        r.pack_long(515893)	#msecs
        r.pack_long(ctime[3])	#hours
        r.pack_long(ctime[4])   #mins
        r.pack_long(ctime[5])   #secs
        r.pack_long(59) 	#hunds
        r.pack_long_signed(int(altzone/60),) #timezone
        r.pack_long(310) 	#tinterval
        r.pack_long(ctime[2])   #day
        r.pack_long(ctime[1])   #month
        r.pack_long(ctime[0])   #year
        r.pack_long(ctime[6])   #weekday

        r.pack_long(0)
        return r.get_buffer()

    @classmethod
    def handle_NetServerGetInfo(cls, con, p):
        #3.1.4.17 NetrServerGetInfo (Opnum 21)
        #
        #http://msdn.microsoft.com/en-us/library/cc247243%28v=PROT.13%29.aspx
        #
        #NET_API_STATUS NetrServerGetInfo(
        #  [in, string, unique] SRVSVC_HANDLE ServerName,
        #  [in] DWORD Level,
        #  [out, switch_is(Level)] LPSERVER_INFO InfoStruct
        #);

        p = ndrlib.Unpacker(p.StubData)
        Pointer = p.unpack_pointer()
        ServerName = p.unpack_string()
        Level = p.unpack_long()
        print("ServerName %s Level %i" % (ServerName,Level))

        r = ndrlib.Packer()
        r.pack_long(Level)

        if Level == 101:
            s = SRVSVC.SERVER_INFO_101(r)
            server = ServerName.decode('UTF-16')[2:]
            s.Data = [server, '\0']
            s.pack()

        r.pack_long(0)
        return r.get_buffer()

class ssdpsrv(RPCService):
    uuid = UUID('4b112204-0e19-11d3-b42b-0000f81feb9f').hex


class SVCCTL(RPCService):
    """[MS-SCMR]: Service Control Manager Remote Protocol Specification

    http://msdn.microsoft.com/en-us/library/cc245832%28v=PROT.10%29.aspx
    """
    uuid = UUID('367abb81-9844-35f1-ad32-98f038001003').hex
    version_major = 0
    version_minor = 0

    ops = {
        0 : "CloseServiceHandle",
        24: "CreateServiceA",
        27: "OpenSCManagerA",
    }

    @classmethod
    def handle_CloseServiceHandle(cls, con, p):
        # DWORD RCloseServiceHandle(
        # 	[in, out] LPSC_RPC_HANDLE hSCObject
        # );
        pass

    @classmethod
    def handle_CreateServiceA(cls, con, p):
        # DWORD RCreateServiceA(
        # 	[in] SC_RPC_HANDLE hSCManager,
        # 	[in, string, range(0, SC_MAX_NAME_LENGTH)] LPSTR lpServiceName,
        # 	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)] LPSTR lpDisplayName,
        # 	[in] DWORD dwDesiredAccess,
        # 	[in] DWORD dwServiceType,
        # 	[in] DWORD dwStartType,
        # 	[in] DWORD dwErrorControl,
        # 	[in, string, range(0, SC_MAX_PATH_LENGTH)] LPSTR lpBinaryPathName,
        # 	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)] LPSTR lpLoadOrderGroup,
        # 	[in, out, unique] LPDWORD lpdwTagId,
        # 	[in, unique, size_is(dwDependSize)] LPBYTE lpDependencies,
        # 	[in, range(0, SC_MAX_DEPEND_SIZE)] DWORD dwDependSize,
        # 	[in, string, unique, range(0, SC_MAX_ACCOUNT_NAME_LENGTH)] LPSTR lpServiceStartName,
        # 	[in, unique, size_is(dwPwSize)] LPBYTE lpPassword,
        # 	[in, range(0, SC_MAX_PWD_SIZE)] DWORD dwPwSize,
        # 	[out] LPSC_RPC_HANDLE lpServiceHandle
        # );
        pass


    @classmethod
    def handle_OpenSCManagerA(cls, con, p):
        # DWORD ROpenSCManagerA(
        # 	[in, string, unique, range(0, SC_MAX_COMPUTER_NAME_LENGTH)] SVCCTL_HANDLEA lpMachineName,
        # 	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)] LPSTR lpDatabaseName,
        # 	[in] DWORD dwDesiredAccess,
        # 	[out] LPSC_RPC_HANDLE lpScHandle
        # );
        pass

class tapsrv(RPCService):
    uuid = UUID('2f5f6520-ca46-1067-b319-00dd010662da').hex


class TerminalServerLicensing(RPCService):
    uuid = UUID('3d267954-eeb7-11d1-b94e-00c04fa3080d').hex


class trkwks(RPCService):
    uuid = UUID('300f3532-38cc-11d0-a3f0-0020af6b0add').hex


class w32time(RPCService):
    uuid = UUID('8fb6d884-2388-11d0-8c35-00c04fda2795').hex


#class winipsec(RPCService):
#	uuid = UUID('12345678-1234-abcd-ef00-0123456789ab').hex


class winreg(RPCService):
    uuid = UUID('338cd001-2244-31f1-aaaa-900038001003').hex


class winsif(RPCService):
    uuid = UUID('45f52c28-7f9f-101a-b52b-08002b2efabe').hex


class winstation_rpc(RPCService):
    uuid = UUID('5ca4a760-ebb1-11cf-8611-00a0245420ed').hex


class WKSSVC(RPCService):
    uuid = UUID('6bffd098-a112-3610-9833-46c3f87e345a').hex

    ops = {
        0x1b: "NetAddAlternateComputerName"
    }
    vulns  = {
        0x1b: "MS03-39",
    }

    @classmethod
    def handle_NetAddAlternateComputerName(cls, con, p):
        # MS03-039
        pass
