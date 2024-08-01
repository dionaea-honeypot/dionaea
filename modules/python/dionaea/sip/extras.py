# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2011-2020 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Some helper functions.
"""
import datetime
import logging
import os
import pprint
import re
import sqlite3
import struct
import time

logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)

DEFAULT_SDP = """
v=0
o=- 1304279835 1 IN {addrtype} {unicast_address}
s=SIP Session
c=IN {addrtype} {unicast_address}
t=0 0
[audio_port]
m=audio {audio_port} RTP/AVP 111 0 8 9 101 120
a=sendrecv
a=rtpmap:111 Speex/16000/1
a=fmtp:111 sr=16000,mode=any
a=rtpmap:0 PCMU/8000/1
a=rtpmap:8 PCMA/8000/1
a=rtpmap:9 G722/8000/1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16,32,36
a=rtpmap:120 NSE/8000
a=fmtp:120 192-193
[/audio_port]
[video_port]
m=video {video_port} RTP/AVP 34 96 97
c=IN {addrtype} {unicast_address}
a=rtpmap:34 H263/90000
a=fmtp:34 QCIF=2
a=rtpmap:96 H263-1998/90000
a=fmtp:96 QCIF=2
a=rtpmap:97 H263-N800/90000
[/video_port]
"""


def int2bytes(value):
    """
    Convert integer to bytes
    """
    return bytes(str(value), "utf-8")


class ErrorWithResponse(Exception):
    def __init__(self, msg, response_code, status_message):
        self._msg = msg
        self._response_code = response_code
        self._status_message = status_message

    def create_response(self):
        return self._msg.create_response(self._response_code, self._status_message)


class SipConfig(object):
    """
    This class helps to access the config values.
    """

    def __init__(self, config=None):
        """
        :param config: The config dict from dionaea
        :type config: Dict

        """
        if config is None:
            config = {}

        self.root_path = os.getcwd()

        self.users = os.path.join(self.root_path, config.get("users", "var/lib/dionaea/sip/accounts.sqlite"))

        self._conn = sqlite3.connect(self.users)
        self._cur = self._conn.cursor()

        if not self._table_exists("users"):
            self._cur.execute("CREATE TABLE IF NOT EXISTS users (username STRING, password STRING, personality STRING, pickup_delay_min INTEGER, pickup_delay_max INTEGER, action STRING, sdp STRING)")
            # example without password
            self._cur.execute("INSERT INTO users (username, password, personality, pickup_delay_min, pickup_delay_max, action, sdp) VALUES ('^[0-9]{1,12}$', '', 'default', 5, 10, 'default', 'default')")
            # example with password
            self._cur.execute("INSERT INTO users (username, password, personality, pickup_delay_min, pickup_delay_max, action, sdp) VALUES ('^pw[0-9]{1,12}$', 'password', 'default', 5, 10, 'default', 'default')")

        if not self._table_exists("sdp"):
            self._cur.execute("CREATE TABLE IF NOT EXISTS sdp (name STRING, sdp STRING)")
            self._cur.execute("INSERT INTO sdp (name, sdp) VALUES ('default', ?)", (DEFAULT_SDP,))

        # set default values
        self.personalities = {
            "default": {
                "domain": "localhost",
                "name": "",
                "personality": "generic",
                "serve": [],
                "default_sdp": "default",
                "handle": ["REGISTER", "OPTIONS", "INVITE", "CANCEL", "BYE", "ACK"]
            }
        }

        for pers_name, personality in config.get("personalities", {}).items():
            if pers_name not in self.personalities:
                self.personalities[pers_name] = {}

            for n in ["domain", "name", "personality", "serve", "default_sdp", "handle"]:
                v = personality.get(n, self.personalities["default"][n])
                if type(v) != type(self.personalities["default"][n]):
                    v = self.personalities["default"][n]
                # convert values
                if n == "handle":
                    # convert all values to uppercase
                    v = [t.upper() for t in v]

                self.personalities[pers_name][n] = v

        self.actions = config.get("actions", {})

        # ToDo: read values from config
        # set default values
        self.timers = {
            "idle": {
                "timeout": 30
            }
        }

        self._rtp = config.get("rtp", {})

        rtp_enable = self._rtp.get("enable", False)
        self._rtp["enable"] = rtp_enable

        self.actions = config.get("actions", {})

    def _table_exists(self, name):
        """
        Check if table exists
        """
        ret = self._cur.execute("SELECT name FROM sqlite_master WHERE type='table' and name=?", (name,))
        if ret.fetchone() is None:
            return False
        return True

    def get_action(self, name):
        # ToDo:
        #return (func, params)
        pass

    def get_handlers_by_personality(self, personality):
        if not personality in self.personalities:
            personality = "default"

        return self.personalities[personality]["handle"]

    def get_timer(self, name):
        if not name in self.timers:
            return False

        timer = self.timers[name]

        return Timer(
            timeout = timer["timeout"]
        )

    def get_user_by_username(self, personality, username):
        def regexp(expr, value):
            if type(expr) != str:
                expr = str(expr)
            regex = re.compile(expr)
            return regex.match(value) is not None

        conn = sqlite3.connect(self.users)

        sqlite3.enable_callback_tracebacks(True)
        conn.create_function("regexp", 2, regexp)

        if username is None:
            username = b""

        username = username.decode("utf-8")

        cur = conn.cursor()
        cur.execute("SELECT username, password, pickup_delay_min, pickup_delay_max, action, sdp FROM users WHERE personality = ? AND ? REGEXP username", (personality, username))
        row = cur.fetchone()

        if row is None:
            return None

        password = row[1]
        if type(password) == int:
            password = str(password)

        # ToDo: sdp is not used! Recheck!!!
        sdp = row[5]
        if sdp == '' or sdp is None:
            sdp = self.personalities[personality].default_sdp

        return User(
            username=username,
            username_regex=row[0],
            password=password,
            pickup_delay_min=row[2],
            pickup_delay_max=row[3],
            action=row[4],
            sdp=row[5]
        )

    def get_personality_by_address(self, address):
        for pers_name, personality in self.personalities.items():
            for serve in personality["serve"]:
                if serve == address:
                    return pers_name
        return "default"

    def get_rtp(self, msg_stack=None):
        if msg_stack is None:
            msg_stack = []

        pcap_conf = self._rtp.get("pcap", {})
        return RTP(
            path=pcap_conf.get("path", "var/dionaea/rtp/{personality}/%Y-%m-%d/"),
            filename=pcap_conf.get("filename", "%H:%M:%S_{remote_host}_{remote_port}_in.pcap"),
            enable=self._rtp.get("enable", False),
            mode=self._rtp.get("mode", ["pcap"])
        )

    def get_pcap(self):
        pcap_conf = self._rtp.get("pcap", {})
        return PCAP(
            path=pcap_conf.get("path", "var/dionaea/rtp/{personality}/%Y-%m-%d/"),
            filename=pcap_conf.get("filename", "%H:%M:%S_{remote_host}_{remote_port}_in.pcap"),
        )

    def get_sdp_by_name(self, name, media_ports, **params):
        """
        Fetch the SDP content from the database and add missing values.
        """
        logger.debug("Loading sdp with: params = %s, media_ports %s", pprint.pformat(params), pprint.pformat(media_ports))
        ret = self._cur.execute("SELECT sdp FROM sdp WHERE name='?'")
        data = ret.fetchone()

        if data is None:
            # try to fetch the default sdp from the db
            ret = self._cur.execute("SELECT sdp FROM sdp WHERE name='default'")
            data = ret.fetchone()

        if data is None:
            data = (DEFAULT_SDP,)

        sdp = data[0]
        for n,v in media_ports.items():
            if v is None:
                sdp = re.sub("\\[" + n +"\\].*\\[\\/" + n + "\\]", "", sdp, 0, re.DOTALL)
            else:
                params[n] = v

        sdp = sdp.format(**params)
        return bytes(sdp, "utf-8")

    def get_sdp_media_port_names(self, name):
        """
        Find all media ports.
        """
        ret = self._cur.execute("SELECT sdp FROM sdp WHERE name='?'")
        data = ret.fetchone()

        if data is None:
            # try to fetch the default sdp from the db
            ret = self._cur.execute("SELECT sdp FROM sdp WHERE name='default'")
            data = ret.fetchone()

        if data is None:
            data = (DEFAULT_SDP,)

        media_ports = re.findall("{(audio_port[0-9]*|video_port[0-9]*)}", data[0])

        return media_ports

    def is_handled_by_personality(self, handler_name, personality = "default"):
        """
        Check if dionaea handles the given SIP-Method
        """
        if personality in self.personalities:
            personality = "default"

        if handler_name.upper() in self.personalities[personality]["handle"]:
            return True

        return False


class PCAP(object):
    def __init__(self, path, filename):
        self.path = path
        self.filename = filename
        self._fp = None

    def __del__(self):
        if self._fp is not None:
            self._fp.close()

    def _carry_arround_add(self, a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)

    def _ip_checksum(self, data):
        s = 0
        for i in range(0, len(data), 2):
            word = data[i] + (data[i + 1] << 8)
            s = self._carry_arround_add(s, word)
        return ~s & 0xffff

    def close(self):
        if self._fp is not None:
            self._fp.close()
        self._fp = None

    def open(self, msg_stack, **params):
        path = self.path.format(**params)
        today = datetime.datetime.now()
        path = today.strftime(path)
        #'%H:%M:%S_{remote_host}_{remote_port}_in.rtp'
        filename = today.strftime(self.filename)
        filename = filename.format(**params)
        # ToDo: error check
        try:
            if not os.path.exists(path):
                os.makedirs(path)
        except:
            logger.info("Can't create RTP-Dump dir: %s", path)

        try:
            self._fp = open(os.path.join(path, filename), "wb")
        except:
            logger.warning("Can't create RTP-Dump file: %s", os.path.join(path, filename))

        if self._fp is None:
            return False

        # write pcap global header
        self._fp.write(b"\xd4\xc3\xb2\xa1")
        # version 2.4
        self._fp.write(b"\x02\x00\x04\x00")
        # GMT to local correction
        self._fp.write(b"\x00\x00\x00\x00")
        # accuracy of timestamps
        self._fp.write(b"\x00\x00\x00\x00")
        # max length of captured packets, in octets
        self._fp.write(b"\xff\xff\x00\x00")
        # data link type (1 = Ethernet) http://www.tcpdump.org/linktypes.html
        self._fp.write(b"\x01\x00\x00\x00")

        for msg in msg_stack:
            t = msg[1].time
            ts = int(t)
            tm = int((t - ts) * 1000000)

            src_port = 5060
            dst_port = 5060
            if msg[0] == "in":
                src_ether = b"\x00\x00\x00\x00\x00\x02"
                src_host = b"\x0A\x00\x00\x02" # 10.0.0.2
                dst_ether = b"\x00\x00\x00\x00\x00\x01"
                dst_host = b"\x0A\x00\x00\x01" # 10.0.0.1
            else:
                src_ether = b"\x00\x00\x00\x00\x00\x01"
                src_host = b"\x0A\x00\x00\x01" # 10.0.0.1
                dst_ether = b"\x00\x00\x00\x00\x00\x02"
                dst_host = b"\x0A\x00\x00\x02" # 10.0.0.2

            self.write(ts=ts, tm=tm, src_ether=src_ether, src_host=src_host, src_port=src_port, dst_ether=dst_ether, dst_host=dst_host, dst_port=dst_port, data=msg[1].dumps())

    def write(self, ts=None, tm=None, src_ether=b"\x00\x00\x00\x00\x00\x02", src_host=b"\x0A\x00\x00\x02", src_port=5060, dst_ether=b"\x00\x00\x00\x00\x00\x01", dst_host=b"\x0A\x00\x00\x01", dst_port=5060, data=b""):
        if self._fp is None:
            return

        if ts is None or tm is None:
            t = time.time()
            ts = int(t)
            tm = int((t - ts) * 1000000)

        src_ether = b"\x00\x00\x00\x00\x00\x02"
        src_host = b"\x0A\x00\x00\x02" # 10.0.0.2
        dst_ether = b"\x00\x00\x00\x00\x00\x01"
        dst_host = b"\x0A\x00\x00\x01" # 10.0.0.1

        # udp header
        udp = struct.pack(">H", src_port)  # port src
        udp = udp + struct.pack(">H", dst_port) # port dst
        udp = udp + struct.pack(">H", len(data) + 8) # length
        udp = udp + struct.pack(">H", 0) # checksum
        udp = udp + data

        # IPv4 header
        ip = b"\x45" # version + header length 20bytes
        ip = ip + b"\x00"
        ip = ip + struct.pack(">H", len(udp) + 20) # pkt length
        ip = ip + b"\x00\x00" # identification
        ip = ip + b"\x40\x00" # flags(do not fragment) + fragment offset(0)
        ip = ip + b"\x40\x11" # ttl(64) + protocol(udp)
        ip = ip + b"\x00\x00" # header checksum
        ip = ip + dst_host #b"\x0A\x00\x00\x01" # ip src
        ip = ip + src_host #b"\x0A\x00\x00\x02" # ip dst

        # add checksum to ip header
        ip = ip[:10] + struct.pack("<H", self._ip_checksum(ip)) + ip[12:]

        # ethernet header
        ether = src_ether # MAC src
        ether = ether + dst_ether # MAC dst
        ether = ether + b"\x08\x00" # pkt type IPv4

        pkt = ether + ip + udp

        # pcap packet header
        pcap = struct.pack("i", ts) # time seconds
        pcap = pcap + struct.pack("i", tm) # microseconds
        pcap = pcap + struct.pack("i", len(pkt)) # length captured
        pcap = pcap + struct.pack("i", len(pkt)) # real length
        pcap = pcap + pkt

        self._fp.write(pcap)


class Timer(object):
    def __init__(self, **kwargs):
        self.timeout = kwargs.get("timeout", 30)


class User(object):
    def __init__(self, **kwargs):
        self.realm = kwargs.get("realm", "test")
        self.username = kwargs.get("username", "")
        self.username_regex = kwargs.get("username_regex", "")
        self.password = kwargs.get("password", "")
        self.pickup_delay_min = kwargs.get("pickup_delay_min", 5)
        self.pickup_delay_max = kwargs.get("pickup_delay_max", 10)
        self.action = kwargs.get("action", "default")
        self.sdp = kwargs.get("sdp", "default")


def msg_to_icd(msg, d=None):
    def via_to_dict(v, d=None):
        if d is None:
            d = {}
        for i in ['protocol', 'address', 'port', '_params']:
            d[i] = v.__dict__[i]

        return d

    def uri_to_dict(u, d=None):
        if d is None:
            d = {}
        for i in ['scheme', 'user', 'password', 'host', 'port', 'params', 'headers']:
            d[i] = u.__dict__[i]
        return d

    def addr_to_dict(a, d=None):
        if d is None:
            d = {}

        tmp_values = {
            'display_name': None,
            'uri': uri_to_dict,
            #'must_quote':None,
            'params': None
        }

        for k, v in tmp_values.items():
            if v is None:
                d[k] = a.__dict__[k]
            else:
                d[k] = v(a.__dict__[k])
        return d

    def connectiondata_to_dict(c, d=None):
        if d is None: d = {}
        for i in ['addrtype', 'connection_address', 'nettype', 'number_of_addresses', 'ttl']:
            d[i] = c.__dict__[i]
        return d

    def origin_to_dict(o, d=None):
        if d is None: d = {}
        for i in ['addrtype', 'nettype', 'sess_id', 'sess_version', 'unicast_address', 'username']:
            d[i] = o.__dict__[i]
        return d

    def media_to_dict(m, d=None):
        if d is None: d = {}
        # 'attributes'
        for i in ['fmt', 'media', 'number_of_ports', 'port', 'proto']:
            d[i] = m.__dict__[i]
        return d

    def sdp_to_dict(b, d=None):
        if b is None:
            return None
        if d is None:
            d = {}
        d['c']= connectiondata_to_dict(b[b'c'])
        d['o']= origin_to_dict(b[b'o'])
        d['m']= [media_to_dict(i) for i in b[b'm']]
        return d

    def allow_to_list(a):
        if a is None:
            return []
        allow=[]
        for value in a:
            for val in value._value.decode('ascii').split(','):
                allow.append(val.strip())
        return allow

    if d is None:
        d = {}
    d.set('method', msg.method)
    d.set('call_id', msg.headers.get('call-id').value)
    d.set('addr', addr_to_dict(msg.uri))
    d.set('via', [via_to_dict(i._value) for i in msg.headers.get('via')])
    d.set('to', addr_to_dict(msg.headers.get('to')._value))
    d.set('contact', addr_to_dict(msg.headers.get('to')._value))
    d.set('from', [addr_to_dict(f._value) for f in msg.headers.get('from')])
    d.set('sdp', sdp_to_dict(msg.sdp))
    if msg.headers.get('allow') is not None:
        d.set('allow',allow_to_list(msg.headers.get('allow')))
    else:
        d.set('allow',[])
    if msg.headers.get('user-agent') is not None:
        d.set('user_agent', msg.headers.get('user-agent')._value)
    else:
        d.set('user_agent',None)
    print(d)
    return d
