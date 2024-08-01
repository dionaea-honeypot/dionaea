# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import re


class Command(object):
    @classmethod
    def from_line(cls, cmd_line):
        for cmd_cls in [Stats, StorageCommand, Decrement, Delete, Increment, Get, Touch]:
            cmd = cmd_cls.from_line(cmd_line)
            if cmd is not None:
                return cmd


class Decrement(Command):
    name = "decr"
    regex_cmd = re.compile(r"^decr (?P<key>\w+) (?P<value>\d+)( (?P<noreply>noreply))?$")

    def __init__(self, key=None, value=0, no_reply=False):
        self.key = key
        self.value = value

    @classmethod
    def from_line(cls, cmd_line):
        m = cls.regex_cmd.match(cmd_line)
        if m:
            return cls(
                key=m.group("key"),
                value=int(m.group("value")),
                no_reply=m.group("noreply")
            )


class Delete(Command):
    name = "delete"
    regex_cmd = re.compile(r"^(?P<command>\w+) (?P<key>\w+)( (?P<noreply>noreply))?$")

    def __init__(self, key=None, no_reply=None):
        self.key = key
        self.no_reply = no_reply

    @classmethod
    def from_line(cls, cmd_line):
        m = cls.regex_cmd.match(cmd_line)
        if m and m.group("command") == b"delete":
            return cls(
                key=m.group("key"),
                no_reply=m.group("noreply")
            )


class Get(Command):
    name = "get"

    def __init__(self, keys=None):
        if keys is None:
            keys = []
        self.keys = keys

    @classmethod
    def from_line(cls, cmd_line):
        cmd_parts = cmd_line.split(b" ")
        if len(cmd_parts) == 0:
            return None
        if cmd_parts[0] == b"get" or cmd_parts[0] == b"gets":
            return cls(keys=cmd_parts[1:])
        return None


class Increment(Command):
    name = "incr"
    regex_cmd = re.compile(r"^incr (?P<key>\w+) (?P<value>\d+)( (?P<noreply>noreply))?$")

    def __init__(self, key=None, value=0, no_reply=False):
        self.key = key
        self.value = value

    @classmethod
    def from_line(cls, cmd_line):
        m = cls.regex_cmd.match(cmd_line)
        if m:
            return cls(
                key=m.group("key"),
                value=int(m.group("value")),
                no_reply=m.group("noreply")
            )


class StorageCommand(Command):
    regex_cmd = re.compile(r"^(?P<command>\w+) (?P<key>\w+) (?P<flags>\d+) (?P<exptime>\d+) (?P<byte_count>\d+)( (?P<noreply>noreply))?")

    def __init__(self, key=None, flags=None, exptime=None, byte_count=None, noreply=None):
        self.key = key
        self.flags = flags
        self.exptime = exptime
        self.byte_count = byte_count
        self.noreply = noreply

    @classmethod
    def from_line(cls, cmd_line):
        cmd_classes = {
            b"add": Add,
            b"append": Append,
            b"prepend": Prepend,
            b"replace": Replace,
            b"set": Set
        }
        m = cls.regex_cmd.match(cmd_line)
        if m:
            cmd_class = cmd_classes.get(m.group("command"))
            if cmd_class is None:
                return None

            return cmd_class(
                key=m.group("key"),
                flags=m.group("flags"),
                exptime=m.group("exptime"),
                byte_count=int(m.group("byte_count")),
                noreply=m.group("noreply")
            )
        return None


class Add(StorageCommand):
    name = "add"


class Append(StorageCommand):
    name = "append"


class Prepend(StorageCommand):
    name = "prepend"


class Replace(StorageCommand):
    name = "replace"


class Set(StorageCommand):
    name = "set"


class Stats(Command):
    name = "stats"

    def __init__(self, arguments=None):
        if arguments is None:
            arguments = []
        self.arguments = arguments

    @property
    def sub_command(self):
        if len(self.arguments) > 0:
            return self.arguments[0]
        return None

    @classmethod
    def from_line(cls, cmd_line):
        cmd_parts = cmd_line.split(b" ")
        if len(cmd_parts) == 0:
            return None
        if cmd_parts[0] == b"stats":
            return cls(arguments=cmd_parts[1:])
        return None


class Touch(Command):
    name = "touch"
    regex_cmd = re.compile(r"^touch (?P<key>\w+) (?P<exptime>\d+)( (?P<noreply>noreply))?$")

    def __init__(self, key=None, exptime=None, no_reply=None):
        self.key = key
        self.exptime = exptime
        self.no_reply = no_reply

    @classmethod
    def from_line(cls, cmd_line):
        m = cls.regex_cmd.match(cmd_line)
        if m:
            return cls(
                key=m.group("key"),
                exptime=m.group("exptime"),
                no_reply=m.group("noreply")
            )
        return None
