# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2011-2020 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import re
import logging
import time

try:
    from dionaea.sip import rfc2396, rfc4566
    from dionaea.sip.extras import int2bytes, ErrorWithResponse
except:
    import rfc2396, rfc4566
    from extras import int2bytes, ErrorWithResponse

logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)

# For more information see RFC3261 Section: 21 Response Codes
# http://tools.ietf.org/html/rfc3261#section-21

# Provisional 1xx
TRYING = 100
RINGING = 180
CALL_IS_BEING_FORWARDED = 181
QUEUED = 182
SESSION_PROGRESS = 183

# Successful 2xx
OK = 200

# Redirection 3xx
MULTIPLE_CHOICES = 300
MOVED_PERMANENTLY = 301
MOVED_TEMPORARILY = 302
USE_PROXY = 305
ALTERNATIVE_SERVICE = 380

# Request Failure 4xx
BAD_REQUEST = 400
UNAUTHORIZED = 401
PAYMENT_REQUIRED = 402
FORBIDDEN = 403
NOT_FOUND = 404
METHOD_NOT_ALLOWED = 405
NOT_ACCEPTABLE = 406
PROXY_AUTHENTICATION_REQUIRED = 407
REQUEST_TIMEOUT = 408
GONE = 410
REQUEST_ENTITY_TOO_LARGE = 413
REQUEST_URI_TOO_LARGE = 414
UNSUPPORTED_MEDIA_TYPE = 415
UNSUPPORTED_URI_SCHEME = 416
BAD_EXTENSION = 420
EXTENSION_REQUIRED = 421
INTERVAL_TOO_BRIEF = 423
TEMPORARILY_UNAVAILABLE = 480
CALL_TRANSACTION_DOSE_NOT_EXIST = 481
LOOP_DETECTED = 482
TOO_MANY_HOPS = 483
ADDRESS_INCOMPLETE = 484
AMBIGUOUS = 485
BUSY_HERE = 486
REQUEST_TERMINATED = 487
NOT_ACCEPTABLE_HERE = 488
REQUEST_PENDING = 491
UNDECIPHERABLE = 493

# Server Failure 5xx
INTERNAL_SERVER_ERROR = 500
NOT_IMPLEMENTED = 501
BAD_GATEWAY = 502
SERVICE_UNAVAILABLE = 503
SERVER_TIME_OUT = 504
VERSION_NOT_SUPPORTED = 505
MESSAGE_TOO_LARGE = 513

# Global Failures 6xx
BUSY_EVERYWHERE = 600
DECLINE = 603
DOES_NOT_EXIST_ANYWHERE = 604
NOT_ACCEPTABLE = 606

status_messages = {
    # Provisional 1xx
    100: b"Trying",
    180: b"Ringing",
    181: b"Call Is Being Forwarded",
    182: b"Queued",
    183: b"Session Progress",

    # Successful 2xx
    200: b"OK",

    # Redirection 3xx
    300: b"Multiple Choices",
    301: b"Moved Permanently",
    302: b"Moved Temporarily",
    305: b"Use Proxy",
    380: b"Alternative Service",

    # Request Failure 4xx
    400: b"Bad Request",
    401: b"Unauthorized",
    402: b"Payment Required",
    403: b"Forbidden",
    404: b"Not Found",
    405: b"Method Not Allowed",
    406: b"Not Acceptable",
    407: b"Proxy Authentication Required",
    408: b"Request Timeout",
    410: b"Gone",
    413: b"Request Entity Too Large",
    414: b"Request-URI Too Large",
    415: b"Unsupported Media Type",
    416: b"Unsupported URI Scheme",
    420: b"Bad Extension",
    421: b"Extension Required",
    423: b"Interval Too Brief",
    480: b"Temporarily Unavailable",
    481: b"Call/Transaction Does Not Exist",
    482: b"Loop Detected",
    483: b"Too Many Hops",
    484: b"Address Incomplete",
    485: b"Ambiguous",
    486: b"Busy Here",
    487: b"Request Terminated",
    488: b"Not Acceptable Here",
    491: b"Request Pending",
    493: b"Undecipherable",

    # Server Failure 5xx
    500: b"Internal Server Error",
    501: b"Not Implemented",
    502: b"Bad Gateway",
    503: b"Service Unavailable",
    504: b"Server Time-out",
    505: b"Version Not Supported",
    513: b"Message Too Large",

    # Global Failures 6xx
    600: b"Busy Everywhere",
    603: b"Decline",
    604: b"Does Not Exist Anywhere",
    606: b"Not Acceptable",
}


class SipParsingError(Exception):
    """
    Exception class for errors occurring during SIP message parsing
    """


class CSeq(object):
    """
    Hold the value of an CSeq attribute

    >>> cseq1 = CSeq.froms(b"100 INVITE")
    >>> cseq2 = CSeq(seq = 100, method = b"INVITE")
    >>> print(cseq1.dumps(), cseq2.dumps(), cseq1.seq, cseq1.method)
    b'100 INVITE' b'100 INVITE' 100 b'INVITE'
    """
    def __init__(self, data = None, seq = None, method = None):
        # do we need to convert the data?
        if seq is not None and type(seq) == str:
            seq = int(seq)
        if type(method) == str:
            method = bytes(method, "utf-8")

        self.seq = seq
        self.method = method

    def dumps(self):
        return int2bytes(self.seq) + b" " + self.method

    @classmethod
    def froms(cls,data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        if type(data) == str:
            data = bytes(data, "utf-8")

        d = data.partition(b" ")
        seq = int(d[0].decode("utf-8"))
        method = d[2].strip()
        return (len(data), {'seq':seq,'method':method})


class Header(object):
    """
    >>> print(Header.froms('"John Doe" <sip:john@example.org>', 'to').dumps())
    b'To: "John Doe" <sip:john@example.org>'
    >>> print(Header.froms(b'"John Doe" <sip:john@example.org>', b'to').dumps())
    b'To: "John Doe" <sip:john@example.org>'
    >>> print(Header.froms(b'"John Doe" <sip:john@example.org>;tag=abc123', b'to').dumps())
    b'To: "John Doe" <sip:john@example.org>;tag=abc123'
    >>> print(Header.froms(b'To: "John Doe" <sip:john@example.org>;tag=abc123').dumps())
    b'To: "John Doe" <sip:john@example.org>;tag=abc123'
    """

    _address = [
        b"contact",
        b"from",
        b"record-route",
        b"refer-to",
        b"referred-by",
        b"route",
        b"to"
    ]
    _exception = {
        b"call-id": b"Call-ID",
        b"cseq": b"CSeq",
        b"www-authenticate": b"WWW-Authenticate"
    }

    _header_compact2long = {
        b"c": b"content-type",
        b"e": b"content-encoding",
        b"f": b"from",
        b"i": b"call-id",
        b"k": b"supported",
        b"l": b"content-length",
        b"m": b"contact", # m = moved
        b"s": b"subject",
        b"t": b"to",
        b"v": b"via"
    }

    def __init__(self, name, value = None):
        if type(name) == str:
            name = bytes(name, "utf-8")
        self.name = name.lower()

        if type(value) == str:
            value = bytes(value, "utf-8")
        self._value = value

    def dumps(self):
        """
        Dump the value with header name.
        """
        return self.format_name(self.name) + b": " + self.get_value()

    @classmethod
    def froms(cls, data, name = None):
        return cls(**cls.loads(data, name)[1])

    @classmethod
    def loads(cls, data, name):
        if type(data) == str:
            data = bytes(data, "utf-8")
        if type(name) == str:
            name = bytes(name, "utf-8")

        if name is None:
            data = data.strip()
            d = re.split(b": *", data, 1)
            name = d[0].strip()
            data = d[1].strip()

        name = name.lower()
        name = cls._header_compact2long.get(name, name)

        if type(data) != bytes:
            value = data
        elif name in cls._address:
            # FIXME may cause problems?
            addr = rfc2396.Address.froms(data)
#            addr.must_quote = True
#            l = addr.loads(data)
            # ToDo: use l to parse the rest
            value = addr
        elif name == b"cseq":
            value = CSeq.froms(data)
        elif name == b"via":
            value = Via.froms(data)
        else:
            value = data

        return (len(data), {'name':name,'value':value})

    def format_name(self, name):
        name = name.lower()
        if name in self._exception:
            return self._exception[name]

        names = name.split(b"-")
        names = [n.capitalize() for n in names]

        return b"-".join(names)

    def get_raw(self):
        return self._value

    def get_value(self):
        """
        Prepare the value and return it as bytes.
        """
        if type(self._value) == bytes:
            return self._value
        if type(self._value) == int:
            return int2bytes(self._value)

        return self._value.dumps()

    value = property(get_value)


class Headers(object):

    _single = [
        b"call-id",
        b"content-disposition",
        b"content-length",
        b"content-type",
        b"cseq",
        b"date",
        b"expires",
        b"event",
        b"max-forwards",
        b"organization",
        b"refer-to",
        b"referred-by",
        b"server",
        b"session-expires",
        b"subject",
        b"timestamp",
        b"to",
        b"user-agent"
    ]

    def __init__(self):
        self._headers = {}

    def __getattr__(self, name):
        return self.get(name)

    def __iter__(self):
        return iter(self._headers)

    def append(self, headers, copy = False, name_new = None):
        if headers is None:
            return

        if type(headers) != list:
            headers = [headers]
        for header in headers:
            if copy:
                header = Header.froms(header.dumps())
            if name_new is not None:
                header.name = name_new

            if header.name in self._single:
                self._headers[header.name] = header
            elif header.name in self._headers:
                self._headers[header.name].append(header)
            else:
                self._headers[header.name] = [header]

    def dump_list(self):
        ret = []
        for name, header in self._headers.items():
            if not type(header) == list:
                header = [header]
            for h in header:
                ret.append(h.dumps())

        return ret

    def get(self, name, default = None):
        if type(name) == str:
            name = bytes(name, "utf-8")

        name = name.lower()
        if name not in self._headers:
            return default

        return self._headers[name]

    def items(self):
        return self._headers.items()


class Message(object):
    """
    >>> s = b'ACK sip:alice@example.org SIP/2.0\\r\\n'
    >>> s = s + b'CSeq: 1 ACK\\r\\n'
    >>> s = s + b'Via: SIP/2.0/UDP example.org:5060;branch=foo-bar;rport\\r\\n'
    >>> s = s + b'From: "Bob" <sip:bob@example.org>;tag=123\\r\\n'
    >>> s = s + b'Call-ID: cWhfKU3v\\r\\n'
    >>> s = s + b'To: "Alice" <sip:alice@example.org>\\r\\n'
    >>> s = s + b'Content-Length: 0\\r\\n'
    >>> s = s + b'Max-Forwards: 70\\r\\n'
    >>> s = s + b'\\r\\n'
    >>> m = Message.froms(s)
    >>> print(m.method)
    b'ACK'
    >>> print(m.protocol)
    b'SIP/2.0'
    >>> m.uri
    b'sip:alice@example.org'
    >>> print(m.headers.get(b"to").dumps())
    b'To: "Alice" <sip:alice@example.org>'
    >>> print(m.headers.get(b"call-id").dumps())
    b'Call-ID: cWhfKU3v'
    >>> s = m.dumps()
    >>> # parse the generated message again
    >>> m = Message.froms(s)
    >>> s2 = m.dumps()
    >>> # check if the content is the same
    >>> t1 = s.split(b"\\r\\n")
    >>> t2 = s2.split(b"\\r\\n")
    >>> t1.sort()
    >>> t2.sort()
    >>> print(b"\\r\\n".join(t1) == b"\\r\\n".join(t2))
    True
    >>> s1 = b"INVITE sip:alice@example.org SIP/2.0\\r\\n"
    >>> s1 = s1 + b"Via: SIP/2.0/UDP example.org;branch=foo-bar\\r\\n"
    >>> s1 = s1 + b"To: Alice <sip:alice@home.com>\\r\\n"
    >>> s1 = s1 + b"From: Bob <sip:bob@example.net>;tag=123\\r\\n"
    >>> s1 = s1 + b"Call-ID: cWhfKU3v\\r\\n"
    >>> s1 = s1 + b"CSeq: 123 INVITE\\r\\n"
    >>> s1 = s1 + b"Max-Forwards: 70\\r\\n"
    >>> s1 = s1 + b"Contact: <sip:bob@example.org>\\r\\n"
    >>> s1 = s1 + b"Content-Type: application/sdp\\r\\n"
    >>> s1 = s1 + b"Content-Length: 141\\r\\n\\r\\n"
    >>> s2 = b"v=0\\r\\n"
    >>> s2 = s2 + b"o=bob 12345 23456 IN IP4 192.168.1.1\\r\\n"
    >>> s2 = s2 + b"s=A dionaea test\\r\\n"
    >>> s2 = s2 + b"c=IN IP4 192.168.1.2\\r\\n"
    >>> s2 = s2 + b"t=0 0\\r\\n"
    >>> s2 = s2 + b"m=audio 8080 RTP/AVP 0 8\\r\\n"
    >>> s2 = s2 + b"m=video 8081 RTP/AVP 31\\r\\n"
    >>> s = s1 + s2
    >>> m = Message.froms(s)
    >>> m.sdp[b"v"]
    0
    >>> m.sdp[b"o"].dumps()
    b'bob 12345 23456 IN IP4 192.168.1.1'
    >>> m.sdp[b"s"]
    b'A dionaea test'
    >>> m.sdp[b"c"].dumps()
    b'IN IP4 192.168.1.2'
    """

    def __init__(self, session=None, method = None, uri = None, response_code = None, status_message = None, protocol = None, body = None, headers = None, sdp = None, personality = "default"):
        self.method = method
        self.uri = uri
        self.response_code = response_code
        self.status_message = status_message
        self.protocol = protocol
        self._body = body
        self._personality = personality
        self._session = session

        if headers is None:
            headers = Headers()

        self.headers = headers
        self.sdp = sdp
        #: time of package creation
        self.time = time.time()

    def create_response(self, code, message = None, personality = None):
        logger.info("Creating Response: code=%s, message=%s", code, message)

        if personality is not None:
            self._personality = personality

        res = Message(session=self._session)
        res.protocol = b"SIP/2.0"
        res.response_code = code
        res.status_message = message
        if res.status_message is None:
            if code in status_messages:
                res.status_message = status_messages[code]
            else:
                res.status_message = b""

        if type(res.status_message) == str:
            res.status_message = bytes(res.status_message, "utf-8")

        for name in [b"cseq", b"call-id", b"via"]:
            res.headers.append(self.headers.get(name, None), True)

        # copy headers
        res.headers.append(self.headers.get(b"from", None), True, b"from")
        res.headers.append(self.headers.get(b"to", None), True, b"to")

        # create contact header
        addr = self.headers.get(b"to", None)._value
        uri = rfc2396.URI(
            scheme = addr.uri.scheme,
            user = addr.uri.user,
            host = addr.uri.host,
            port = addr.uri.port
        )

        cont_addr = rfc2396.Address(uri = uri)

        contact = Header(name=b"contact", value = cont_addr)
        res.headers.append(contact)

        handler = self._session.config.get_handlers_by_personality(self._personality)

        res.headers.append(Header(name = b"allow", value = ", ".join(handler)))
        res.headers.append(Header(name = b"content-length", value = 0))

        return res

    def dumps(self):
        # h = Header
        h = []
        if self.method is not None:
            h.append(self.method + b" " + self.uri.dumps() + b" " + self.protocol)
        elif self.response_code is not None:
            h.append(self.protocol + b" " + int2bytes(self.response_code) + b" " + self.status_message)
        else:
            return None

        sdp = b""
        if self.sdp is not None:
            sdp = self.sdp.dumps()
            self.headers.append(Header(name = b"content-type", value = b"application/sdp"))
            self.headers.append(Header(name = b"content-length", value = len(sdp)))

        h = h + self.headers.dump_list()

        return b"\r\n".join(h) + b"\r\n\r\n" + sdp

    @classmethod
    def froms(cls, data, session=None):
        return cls(**cls.loads(data, session=session)[1])

    def header_exist(self, header_name):
        """
        Check if a header with the given name exists
        """
        if type(header_name) == str:
            header_name = bytes(header_name, "utf-8")

        return self.headers_exist([header_name], True)

    def headers_exist(self, headers, overwrite = False):
        if not overwrite:
            headers = headers + [b"to", b"from", b"call-id", b"cseq", b"contact"]

        for header in headers:
            if self.headers.get(header) is None:
                logger.warn("Header missing: %r", header)
                return False

        return True

    @classmethod
    def loads(cls, data, session=None):
        """
        Parse a SIP-Message and return the used bytes

        :return: bytes used
        """
        # End Of Head
        if type(data) == bytes:
            pos = re.search(b"\r?\n\r?\n", data)
        else:
            pos = re.search("\r?\n\r?\n", data)

        if pos is None:
            return (0, {})

        # length of used data
        l = pos.end()

        # header without empty line
        header = data[:pos.start()]
        headers_data = re.split(b"\r?\n", header)

        # body without empty line
        body = data[pos.end():]

        # remove first line and parse it
        try:
            h1, h2, h3 = headers_data[0].split(b" ", 2)
        except:
            logger.warning("Can't parse first line of sip message: %s", repr(headers_data[0])[:128])
            raise SipParsingError

        del headers_data[0]

        response_code = None
        status_message = None
        try:
            response_code, protocol, status_message = int(h2), h1, h3
        except:
            method, uri, protocol = h1, rfc2396.Address.froms(h2), h3

        # ToDo: check protocol
        headers = Headers()
        for h in headers_data:
            header = Header.froms(h)
            headers.append(header)

        sdp = None
        try:
            content_length = int(headers.get(b"content-length", None).value)
        except:
            content_length = None

        if content_length is not None:
            if content_length <=  len(body):
                content = body[:content_length]

                content_type = headers.get(b"content-type", None)
                if content_type is not None and content_type.value.lower().strip() == b"application/sdp":
                    try:
                        sdp = rfc4566.SDP.froms(content)
                    except rfc4566.SdpParsingError:
                        msg = Message(**{
                            "session": session,
                            "method": method,
                            "uri": uri,
                            "response_code": response_code,
                            "status_message": status_message,
                            "protocol": protocol,
                            "body": body,
                            "headers": headers
                        })
                        raise ErrorWithResponse(msg, BAD_REQUEST, "Invalid SIP body")

                l += content_length
            else:
                logger.info("Body is to short than the given content-length: Content-Length %d, Body %d", content_length, len(body))

        return (
            l,
            {
                "session": session,
                "method": method,
                "uri": uri,
                "response_code": response_code,
                "status_message": status_message,
                "protocol": protocol,
                "body": body,
                "headers": headers,
                "sdp": sdp
            }
        )

    def set_personality(self, personality):
        self._personality = personality


class Via(object):
    """
    Parse and generate the content of a Via: Header.

    :See: http://tools.ietf.org/html/rfc3261#page-179

    Test strings are taken from RFC3261

    >>> s = b"SIP/2.0/UDP erlang.bell-telephone.com:5060;branch=z9hG4bK87asdks7"
    >>> v = Via.froms(s)
    >>> print(v.port, v.address, v.protocol)
    5060 b'erlang.bell-telephone.com' b'UDP'
    >>> print(v.get_param(b"branch"))
    b'z9hG4bK87asdks7'
    >>> print(s == v.dumps())
    True
    >>> v = Via.froms(b"SIP/2.0/UDP 192.0.2.1:5060 ;received=192.0.2.207;branch=z9hG4bK77asjd")
    >>> print(v.port, v.address, v.protocol)
    5060 b'192.0.2.1' b'UDP'
    >>> print(v.get_param(b"branch"), v.get_param(b"received"))
    b'z9hG4bK77asjd' b'192.0.2.207'
    """

    _syntax = re.compile(r"SIP */ *2\.0 */ *(?P<protocol>[a-zA-Z]+) *(?P<address>[^ :;]*) *(:(?P<port>[0-9]+))?( *; *(?P<params>.*))?")

    def __init__(self, protocol = None, address = None, port = None, params = None):
        if params is None:
            params = []
        self.protocol = protocol
        self.address = address
        self.port = port
        self._params = params

    def dumps(self):
        ret = b"SIP/2.0/" + self.protocol.upper() + b" " + self.address
        if self.port is not None:
            ret = ret + b":" + int2bytes(self.port)

        if self._params is not None and len(self._params) > 0:
            params = []
            for x in self._params:
                if x[1] != b"" and x[1] is not None:
                    params.append(b"=".join(x))
                else:
                    params.append(x[0])
            ret = ret + b";" + b";".join(params)

        return ret

    def get_param(self, name, default = None):
        for x in self._params:
            if x[0] == name:
                return x[1]

        return default

    def set_param(self, name, value):
        for x in self._params:
            if x[0] == name:
                x[1] = value
                return

    @classmethod
    def froms(cls, data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        m = cls._syntax.match(data)
        if not m:
            raise Exception("Error parsing the data")

        protocol = m.group("protocol")
        address = m.group("address")
        port = m.group("port")
        if port is not None:
            try:
                port = int(port)
            except:
                # error parsing port, set default value
                self.port = 5060

        param_data = m.group("params")

        if not param_data:
            raise Exception("Error no parameter given")

        params = []
        # prevent crashes by limiting split count
        # ToDo: needs testing
        for param in re.split(b" *; *", param_data, 64):
            t = re.split(b" *= *", param, 1)
            v = b""
            if len(t) > 1:
                v = t[1]

            params.append((t[0], v))

        return (
            m.end(),
            {
                "protocol": protocol,
                "address": address,
                "port": port,
                "params": params
            }
        )


if __name__ == '__main__':
    import doctest
    doctest.testmod()
