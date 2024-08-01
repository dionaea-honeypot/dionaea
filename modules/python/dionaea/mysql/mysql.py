# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2011 Markus Koetter
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os
import re
import sqlite3
import tempfile

from dionaea.core import incident, connection, g_dionaea
from .include.packets import *

from .var import VarHandler

logger = logging.getLogger('mysqld')

re_show_var = re.compile(
    r"show\s+((?P<global>global)\s+)?variables(\s+like\s+(?P<sep>\"|')(?P<like>.*?)(?P=sep))?",
    re.I
)

re_select_var = re.compile(
    r"select\s+(?P<full_name>@(?P<global>@)?(?P<name>\w+))(\s+limit\s+\d+)?",
    re.I
)


class mysqld(connection):
    shared_config_values = [
        "config",
        "download_dir",
        "download_suffix"
    ]
    vars = VarHandler()

    def __init__(self):
        connection.__init__(self, "tcp")
        self.config = None
        self.state = ""
        self.regex_statement = re.compile(
            r"""([A-Za-z0-9_.]+\(.*?\)+|\(.*?\)+|"(?:[^"]|\"|"")*"+|'[^'](?:|\'|'')*'+|`(?:[^`]|``)*`+|[^ ,]+|,)"""
        )
        self.download_dir = None
        self.download_suffix = ".tmp"

    def apply_config(self, config):
        self.config = config.get("databases")

        dionaea_config = g_dionaea.config().get("dionaea")
        self.download_dir = dionaea_config.get("download.dir")
        self.download_suffix = dionaea_config.get("download.suffix", ".tmp")

        from .var import CFG_VARS
        self.vars.load(CFG_VARS)
        vars = config.get("vars")
        if not isinstance(vars, dict):
            vars = {}

        for name, value in vars.items():
            obj = self.vars.values.get(name)
            if obj is None:
                logger.warning("Config value '%s' does not exist")
                continue
            obj.value = value

    def handle_established(self):
        self.processors()
        self.state = 'greeting'
        var_version = self.vars.values.get("version")
        greeting = MySQL_Server_Greeting(
            ServerVersion="%s\0" % var_version
        )
        a = MySQL_Packet_Header(Number=0) / greeting
        a.show()
        self.send(a.build())
        self._open_db('information_schema')

    def _open_db(self, Database):
        logger.warn("DATABASE opening %s" % Database)
        try:
            p = self.config[Database]['path']
            logger.warn("open db %s -> %s" % (Database, p))
            self.dbh = sqlite3.connect(p)
            self.cursor = self.dbh.cursor()
            self.database = Database
            return True
        except:
            return False

    def _handle_COM_INIT_DB(self, p):
        Database = p.Database.decode('utf-8')
        if self._open_db(Database) == True:
            return MySQL_Result_OK()
        else:
            return MySQL_Result_Error(Message="No such database")

    def _handle_COM_FIELD_LIST(self, p):
        r = []
        query = "PRAGMA table_info(%s);" % p.Table.decode('ascii')[:-1]
        # FIXME sqlite does not allow ? for PRAGMA? I'm not afraid of SQLi here
        # though.
        result = self.cursor.execute(query)
        names = [result.description[x][0] for x in range(len(result.description))]
        result = [dict(zip(names, i)) for i in result]
        for res in result:
            x = MySQL_Result_Field(
                Catalog='def',
                Database=self.database,
                Table=p.Table[:-1],
                ORGTable=p.Table[:-1],
                Name=res['name'].encode('ascii'),
                ORGName=res['name'].encode('ascii'),
                CharSet=33,
                Length=20,
                Type=FIELD_TYPE_VAR_STRING,
                Flags=0,  # 0x4203,
                Decimals=0,
                Default='0'
            )
            r.append(x)
        r.append(MySQL_Result_EOF(ServerStatus=0x002))
        return r

    def _handle_COM_QUERY(self, p):
        r = None
        query = self.regex_statement.findall(p.Query)

        if len(query) > 0 and query[0].lower() == b"select":
            print("foo")
            r = self._handle_com_query_select(p, query[1:])

        elif len(query) > 0 and query[0].lower() == b"show":
            r = self._handle_com_query_show(p, query[1:])

        # ToDo: Support for MySQL_Result_*()
        if isinstance(r, list):
            return r

        if r is True:
            return MySQL_Result_OK(Message="")

        if re.match(b'set ', p.Query, re.I):
            r = MySQL_Result_OK(Message="#2")

        elif re.match(r'select\s+database\s*\(\s*\)$', p.Query, re.I):
            r = [
                MySQL_Result_Header(FieldCount=1),
                MySQL_Result_Field(
                    Catalog='def',
                    Table=b'',
                    Name=b'DATABASE()',
                    Database=b'',
                    ORGName=b'',
                    ORGTable=b'',
                    CharSet=33,
                    Length=34,
                    Type=FIELD_TYPE_VAR_STRING,
                    Flags=FLAG_NOT_NULL,
                    Decimals=0
                ),
                MySQL_Result_EOF(ServerStatus=0x002),
                MySQL_Result_Row_Data(ColumnValues=[self.database]),
                MySQL_Result_EOF(ServerStatus=0x002)
            ]

        elif re.match(r"show\s+databases$", p.Query, re.I):
            r = [
                MySQL_Result_Header(FieldCount=1),
                MySQL_Result_Field(
                    Catalog='def',
                    Table=b'SCHEMATA',
                    Name=b'Database',
                    Database=b'information_schema',
                    ORGName=b'SCHEMA_NAME',
                    ORGTable=b'SCHEMATA',
                    CharSet=33,
                    Length=192,
                    Type=FIELD_TYPE_VAR_STRING,
                    Flags=FLAG_NOT_NULL,
                    Decimals=0
                ),
                MySQL_Result_EOF(ServerStatus=0x002)
            ]

            for i in self.config.keys():
                r.append(MySQL_Result_Row_Data(ColumnValues=[i]))

            # r.append(MySQL_Result_Row_Data(ColumnValues=['information_schema']))
            r.append(MySQL_Result_EOF(ServerStatus=0x002))

        elif re.match(r'show\s+tables$', p.Query, re.I):
            r = [
                MySQL_Result_Header(FieldCount=1),
                MySQL_Result_Field(
                    Catalog='def',
                    Database=self.database.encode("ascii"),
                    Table=b'TABLE_NAMES',
                    Name=b'Tables_in_' + self.database.encode("ascii"),
                    ORGName=b"TABLE_NAME",
                    ORGTable=b"TABLE_NAMES",
                    CharSet=33,
                    Length=192,
                    Type=FIELD_TYPE_VAR_STRING,
                    Flags=FLAG_NOT_NULL,
                    Decimals=0
                ),
                MySQL_Result_EOF(ServerStatus=0x002)
            ]

            result = self.cursor.execute("select tbl_name from sqlite_master where type = 'table'")
            names = [result.description[x][0] for x in range(len(result.description))]
            result = [dict(zip(names, i)) for i in result]
            for res in result:
                x = MySQL_Result_Row_Data(ColumnValues=[res[name] for name in names])
                r.append(x)
            r.append(MySQL_Result_EOF(ServerStatus=0x002))

        elif re.match(b'attach', p.Query, re.I):
            return MySQL_Result_Error(Message="#1064 - You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use")

        else:
            p.show()
            try:
                query = p.Query.decode('utf-8')
                print(query)
                result = self.cursor.execute(query)
                print(result)
                if result.description is None:
                    r = MySQL_Result_OK()
                else:
                    names = [result.description[x][0] for x in range(len(result.description))]
                    print(result)
                    result = [dict(zip(names, i)) for i in result]
                    r = [MySQL_Result_Header(FieldCount=len(names))]
                    for name in names:
                        r.append(
                            MySQL_Result_Field(
                                #Catalog='def',
                                Table=b'',
                                ORGTable=b"",
                                Database=b"",
                                Name=name,
                                CharSet=33,
                                Length=255,
                                Type=FIELD_TYPE_VAR_STRING,
                                Flags=FLAG_NOT_NULL,
                                Decimals=0
                            )
                        )
                    r.append(MySQL_Result_EOF(ServerStatus=0x002))
                    for res in result:
                        x = MySQL_Result_Row_Data(ColumnValues=[res[name] for name in names])
                        # x.show()
                        r.append(x),
                    r.append(MySQL_Result_EOF(ServerStatus=0x002))
            except Exception as e:
                logger.warn("SQL ERROR %s" % e)
                logger.warn("SQL ERROR in %s" % p.Query)
                r = MySQL_Result_Error(Message="Learn SQL!")
        return r

    def _handle_com_query_select(self, p, query):
        """

        :param p:
        :param bytes[] query:
        :return:
        """
        if len(query) == 0:
            return False

        regex_function = re.compile(r"(?P<name>[A-Za-z0-9_.]+)\((?P<args>.*?)\)+")
        regex_url = re.compile(r"(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)")

        m = re_select_var.match(p.Query)
        if m:
            r = []
            var_name = m.group("name").decode("ascii")
            var_full_name = m.group("full_name").decode("ascii")
            var = self.vars.values.get(var_name)
            if var is None:
                return [MySQL_Result_Error(Message="ERROR 1193 (HY000): Unknown system variable '%s'" % var_name)]

            r.append(MySQL_Result_Header(FieldCount=1))
            r.append(
                MySQL_Result_Field(
                    Catalog='def',
                    Name=var_full_name,
                    CharSet=33,
                    Length=75,
                    Type=FIELD_TYPE_VAR_STRING,
                    Flags=FLAG_NOT_NULL,
                    Decimals=0
                )
            )
            r.append(MySQL_Result_EOF(ServerStatus=0x002))

            r.append(
                MySQL_Result_Row_Data(ColumnValues=["%s\0" % var])
            )
            r.append(MySQL_Result_EOF(ServerStatus=0x002))
            return r

        m = regex_function.match(query[0])

        if m and m.group("name") == b"unhex":
            if len(query) < 4:
                return False

            if query[1].lower() != b"into" or query[2].lower() != b"dumpfile":
                return False

            data = m.group("args")
            data = data.strip(b"' ")

            logger.info("Looks like someone tries to dump a hex encoded file")
            try:
                data = bytearray.fromhex(data.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                logger.warning("Unable to decode hex string %r", query[0][2:], exc_info=True)
                return False

            self._report_raw_data(data)
            return True

        # ToDo: move import to top
        if query[0].startswith(b"0x"):
            if len(query) < 4:
                return False

            if query[1].lower() != b"into" or query[2].lower() != b"dumpfile":
                return False

            logger.info("Looks like someone tries to dump a hex encoded file")
            try:
                data = bytearray.fromhex(query[0][2:].decode("ascii"))
            except UnicodeDecodeError as e:
                logger.warning("Unable to decode hex string %r", query[0][2:], exc_info=True)
                return False

            self._report_raw_data(data)
            return True

        if m and m.group("name") == b"xpdl3":
            args = m.group("args")
            m_url = regex_url.search(args)
            if m_url:
                i = incident("dionaea.download.offer")
                i.con = self
                i.url = m_url.group("url")
                i.report()
            return True

        return False

    def _handle_com_query_show(self, p, query):
        """

        :param p:
        :param bytes[] query:
        :return:
        """

        m = re_show_var.match(p.Query)
        if m:
            r = []
            r.append(MySQL_Result_Header(FieldCount=2))
            r.append(
                MySQL_Result_Field(
                    Catalog='def',
                    Name="Variable_name",
                    CharSet=33,
                    Length=75,
                    Type=FIELD_TYPE_VAR_STRING,
                    Flags=FLAG_NOT_NULL,
                    Decimals=0
                )
            )
            r.append(
                MySQL_Result_Field(
                    Catalog='def',
                    Name="Value",
                    CharSet=33,
                    Length=75,
                    Type=FIELD_TYPE_VAR_STRING,
                    Flags=FLAG_NOT_NULL,
                    Decimals=0
                )
            )
            r.append(MySQL_Result_EOF(ServerStatus=0x002))

            var_name = None
            if m.group("like"):
                var_name = re.escape(m.group("like"))
                var_name = var_name.replace(b"%", b".*")
                var_name = re.compile(var_name)

            for name, var in self.vars.values.items():
                if var_name and not var_name.match(name.encode("ascii")):
                    continue
                r.append(
                    MySQL_Result_Row_Data(ColumnValues=[name + '\0', "%s\0" % var])
                )

            r.append(MySQL_Result_EOF(ServerStatus=0x002))

            return r

    def _report_raw_data(self, data):
        """
        Create temporary file and report incident

        :param bytes data: File data
        """
        fp_tmp = tempfile.NamedTemporaryFile(
            delete=False,
            dir=self.download_dir,
            prefix='mysql-',
            suffix=self.download_suffix
        )

        fp_tmp.write(data)

        icd = incident("dionaea.download.complete")
        icd.path = fp_tmp.name
        icd.con = self
        # We need the url for logging
        icd.url = ""
        fp_tmp.close()
        icd.report()
        os.unlink(fp_tmp.name)

    def handle_io_in(self,data):
        offset = 0
        while len(data) - offset >= 4:
            h = MySQL_Packet_Header(data[offset:offset+4])
            r = p = None
            if len(data)-offset < h.Length + 4:
                break

            if self.state == 'greeting':
                self.state = 'online'
                p = MySQL_Client_Authentication(data[offset+4:offset+4+h.Length])
                if p.DatabaseName != b'\x00':
                    Database = p.DatabaseName[:-1]
                    if type(Database) == str:
                        Database = Database.encode('ascii')
                    if self._open_db(Database) == True:
                        r = MySQL_Result_Error(Message="Could not open Database %s" % Database)
                    else:
                        r = MySQL_Result_OK()
                else:
                    r = MySQL_Result_OK()

                i = incident("dionaea.modules.python.mysql.login")
                i.con = self
                i.username = p.User
                i.password = ""
                i.report()

            elif self.state == 'online':
                p = MySQL_Command_Header(data[offset+4:offset+4+h.Length])
                cmd = MySQL_Commands[p.Command]
                m = getattr(self, "_handle_" + cmd, None)
                args = None
                if m is not None:
                    args = []
                    for f in p.payload.fields_desc:
                        if f.name in p.payload.fields:
                            args.append(p.payload.fields[f.name])
                    r = m(p.payload)

                i = incident("dionaea.modules.python.mysql.command")
                i.con = self
                i.command = p.Command
                if args is not None:
                    i.args = args
                i.dump()
                i.report()

            if p is not None:
                h = h / p
            h.show()

            if r is not None:
                if type(r) is not list:
                    r = [r]
                buf = b''
                for i in range(len(r)):
                    rp = r[i]
                    rp = MySQL_Packet_Header(Number=h.Number+1+i) / rp
                    rp.show()
                    buf += rp.build()
                self.send(buf)
            offset += 4 + h.Length
        return offset
