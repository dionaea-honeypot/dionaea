# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2011-2020 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import re

try:
    from dionaea.sip.extras import int2bytes
except Exception:
    from extras import int2bytes

logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)


class Address(object):
    """
    >>> a1 = Address.froms(b"sip:john@example.org")
    >>> b1 = Address.froms(b"<sip:john@example.org>")
    >>> c1 = Address.froms(b'John Doe <sip:john@example.org>')
    >>> d1 = Address.froms(b'"John Doe" <sip:john@example.org>')
    >>> print(a1.dumps() == b1.dumps() and c1.dumps() == d1.dumps())
    True
    >>> print(d1.dumps())
    b'"John Doe" <sip:john@example.org>'
    """
    _syntax = [
        re.compile(r'^(?P<name>[a-zA-Z0-9\-\.\_\+\~\ \t]*)<(?P<uri>[^>]+)>( *; *(?P<params>.*))?'),
        re.compile(r'^(?:"(?P<name>[a-zA-Z0-9\-\.\_\+\~\ \t]+)")[\ \t]*<(?P<uri>[^>]+)>( *; *(?P<params>.*))?'),
        re.compile(r'^[\ \t]*(?P<name>)(?P<uri>[^;]+)( *; *(?P<params>.*))?')
    ]

    def __init__(self, display_name = None, uri = None, must_quote = None, params = None):
        if params is None:
            params = {}

        self.display_name = display_name
        self.uri = uri
        self.must_quote = must_quote
        self.params = params

    def __repr__(self):
        return self.dumps().decode('utf-8')

    def dumps(self):
        r = b""
        if self.display_name:
            r = b'"' + self.display_name + b'"'
            if self.uri:
                r = r + b" "

        if not self.uri:
            return r

        if self.must_quote or (self.display_name is not None and self.display_name != b""):
            r = r + b"<" + self.uri.dumps() + b">"
        else:
            r = r + self.uri.dumps()

        if len(self.params) > 0:
            params = []
            for n,v in self.params.items():
                params.append(b"=".join([n, v]))

            r = r + b";" + b";".join(params)
        return r

    @classmethod
    def froms(cls, data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        """
        Parse an address

        :return: length used
        :rtype: Integer
        """
        if data is None:
            return (0, {})

        for regex in cls._syntax:
            m = regex.match(data)
            if m:
                display_name = m.groups()[0].strip()
                uri = URI.froms(m.groups()[1].strip())
                param_data = m.groupdict()["params"]
                if param_data is None:
                    return (
                        m.end(),
                        {
                            "display_name": display_name,
                            "uri": uri
                        }
                    )

                params = {}
                for param in re.split(b" *; *", param_data):
                    n,s,v = param.partition(b"=")
                    params[n.strip()] = v.strip()

                return (
                    m.end(),
                    {
                        "display_name": display_name,
                        "params": params,
                        "uri": uri
                    }
                )

        return (0, {})


class URI(object):
    """
    >>> print(URI.froms(b"sip:john@example.org").dumps())
    b'sip:john@example.org'
    >>> u = URI.froms(b"sip:foo:bar@example.org:5060;transport=udp;novalue;param=pval?header=val&second=sec_val")
    >>> print(u.scheme, u.user, u.password, u.host, u.port, len(u.params), len(u.headers))
    b'sip' b'foo' b'bar' b'example.org' 5060 3 2
    >>> d = u.dumps()
    >>> u = URI.froms(d)
    >>> print(u.dumps() == d)
    True
    """

    _syntax = re.compile(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9\+\-\.]*):"  # scheme
        + r"(?:(?:(?P<user>[a-zA-Z0-9\-\_\.\!\~\*\'\(\)&=\+\$,;\?\/\%]+)" # user
        + r"(?::(?P<password>[^:@;\?]+))?)@)?" # password
        + r"(?:(?:(?P<host>[^;\?:]*)(?::(?P<port>[\d]+))?))"  # host, port
        + r"(?:;(?P<params>[^\?]*))?" # parameters
        + r"(?:\?(?P<headers>.*))?$" # headers
    )

    def __init__(self, scheme = None, user = None, password = None, host = None, port = None, params = None, headers = None):
        if params is None:
            params = {}
        if headers is None:
            headers = []
        self.scheme = scheme
        self.user = user
        self.password = password
        self.host = host
        self.port = port
        self.params = params
        self.headers = headers

    def __repr__(self):
        return self.dumps().decode('utf-8')

    def dumps(self):
        if self.scheme is None:
            return b"*"

        r = self.scheme + b":"
        if self.user:
            r = r + self.user
            if self.password:
                r = r + b":" + self.password

            r = r + b"@"
        if self.host:
            r = r + self.host
            if self.port:
                r = r + b":" + int2bytes(self.port)

        if len(self.params) > 0:
            r = r + b";" + b"j".join([n + b"=" + v for n,v in self.params.items()])

        if len(self.headers) > 0:
            r = r + b"?" + b"&".join(self.headers)

        return r

    @classmethod
    def froms(cls, data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        if data:
            m = cls._syntax.match(data)
            if not m:
                try:
                    data = bytes(data, "utf-8")
                    logger.info("Can't parse the URI: %s", data)
                except Exception as e:
                    logger.info("Can't parse or convert the URI: %s", e)

                return (0, {})

            port = m.group("port")
            # ToDo: error check
            try:
                if type(port) == bytes or type(port) == str:
                    port = int(port)
            except Exception as e:
                logger.info("%s", e)

            params = {}
            if m.group("params"):
                for param in m.group("params").split(b";"):
                    t = param.partition(b"=")
                    n = t[0].strip()
                    v = t[2].strip()
                    params[n] = v

            headers = []
            if m.group("headers"):
                headers = m.group("headers").split(b"&")

            return (
                m.end(),
                {
                    "scheme": m.group("scheme"),
                    "user": m.group("user"),
                    "password": m.group("password"),
                    "host": m.group("host"),
                    "port": port,
                    "headers": headers,
                    "params": params
                }
            )

        return (0, {})

if __name__ == '__main__':
    import doctest
    doctest.testmod()
