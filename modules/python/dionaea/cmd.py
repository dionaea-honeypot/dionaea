# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter & Mark Schloesser
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import IHandlerLoader
from dionaea.core import ihandler, incident
from dionaea.core import connection
import logging

logger = logging.getLogger('cmd')
logger.setLevel(logging.DEBUG)


class CMDShellHandlerLoader(IHandlerLoader):
    name = "cmdshell"

    @classmethod
    def start(cls, config=None):
        return cmdshellhandler("dionaea.service.shell.*", config=config)


class cmdexe:
    def __init__(self, w):
        self.specials = [' ', '\t', '"', '\\']
        if not w == None:
            self.send = w
        else:
            self.send = self.void
        self.files = {}
        self.cwd = 'C:\\WINDOWS\\System32'


    def handle_io_in(self, data):
        logger.debug(data)
#        self.send(data)
        c = True
        dlen = len(data)
        logger.debug("DATA: %s" % (data))
        while c:
            data,line,c = self.line(data)
            logger.debug("LINE: %s" % (line))
            cmd,args,redir = self.parse(line)
            logger.debug("CMD: %s %s %s" % (cmd, args, redir))
            if not cmd:
                continue

            out,err = self.execute(cmd,args)
            logger.debug("DATA: %s" % (data))
            self.redir(out, err, redir)
        self.send(self.cwd + '>')
        return dlen-len(data)

    def redir (self, out, err, redir):
        if out != None:
            if redir != None:
                redir = redir.decode()
                redir = redir.strip()
                if redir.startswith('>>'):
                    target = redir[2:]
                elif redir.startswith('>'):
                    target = redir[1:]
                    if target in self.files:
                        del self.files[target]
                if target:
                    target = target.strip()
                    target = target.rstrip()
                    if not target in self.files:
                        self.files[target] = ""
                    self.files[target] += out
                    logger.debug("file %s = %s" % (target,self.files[target]))
            else:
                self.send(out)

        if err != None:
            self.send(err)

    def execute(self, cmd, args):
        cmd = cmd.upper()
        if cmd.endswith(".EXE"):
            cmd = cmd[:len(cmd)-4]
        method = getattr(self, "cmd_" + cmd, None)
        if method is not None:
            return method(args)
        else:
            return None,"Command not found"
        return None,None

    def cmd_ECHO(self, args):
        out = " ".join(args) + '\n'
        logger.debug("echo %s" % (out))
        return out,None

    def cmd_FTP(self, args):
        out = "downloading ..."
        # ftp [-v] [-d] [-i] [-n] [-g] [-s:filename] [-a] [-w:Windowsize] [-A]     [host]
        host = None
        port = 21
        user = None
        passwd = "guest"
        fpath = ""
        dfile = ""
        ftpmode = ''
        autoconnect = True
        cmdfile = None

        for i in range(len(args)):
            if args[i][0] == '-':
                for j in range(1,len(args[i])):
                    if args[i][j] == 'v':
                        continue
                    elif args[i][j] == 'd':
                        continue
                    elif args[i][j] == 'i':
                        continue
                    elif args[i][j] == 'n':
                        autoconnect = False
                    elif args[i][j] == 'g':
                        continue
                    elif args[i][j] == 's':
                        cmdfile = args[i][j+2:]
                        break
                    elif args[i][j] == 'w':
                        break
                    elif args[i][j] == 'A':
                        user = 'anonymous'
                        passwd = 'guest'
            else:
                if host != False:
                    host = args[i]

        if cmdfile == None:
            return "failed downloading",None

        file = self.files[cmdfile]
        lines = file.split('\n')
        state = 'NEXT_IS_SOMETHING'
        for i in range(len(lines)):
            line = lines[i]
            logger.debug("FTP PARSER STATE {}".format(state))
            logger.debug("FTP CMD LINE: %s" % (line) )
            args = line.split()
            if len(args) == 0:
                continue
            logger.debug("FTP CMD ARGS: %s" % (args) )
            if state == 'NEXT_IS_SOMETHING':
                if args[0] == 'open':
                    if len(args) == 1:
                        state = 'NEXT_IS_HOST'
                    else:
                        host = args[1]
                        if len(args) == 3:
                            port = int(args[2])
                        else:
                            port = 21
                    if autoconnect == True and user == None:
                        state = 'NEXT_IS_USER'
                    else:
                        state = 'NEXT_IS_SOMETHING'
                elif args[0] == 'user':
                    if user != None:
                        logger.debug("State error USER")
                    else:
                        if len(args) >= 1:
                            state = 'NEXT_IS_USER'
                        if len(args) >= 2:
                            user = args[1]
                            state = 'NEXT_IS_PASS'
                        if len(args) == 3:
                            passwd = args[2]
                            state = 'NEXT_IS_SOMETHING'
                elif args[0] == 'get':
                    if len(args) == 1:
                        state = 'NEXT_IS_FILE'
                    elif len(args) == 2:
                        dfile = args[1]
                        i = incident("dionaea.download.offer")
                        if isinstance(self, connection):
                            i.con = self
                        elif hasattr(self, 'con') and isinstance(self.con, connection):
                            i.con = self.con
                        i.url = "ftp://%s:%s@%s:%i/%s" % (
                            user,passwd,host,port,dfile)
                        i.ftpmode = ftpmode
                        i.report()
                elif args[0] == 'cd':
                    if len(args) == 1:
                        state = 'NEXT_IS_PATH'
                    elif len(args) == 2:
                        fpath = args[1]
                elif args[0] == 'binary' or args[0] == 'bin':
                    ftpmode = 'binary'

            elif state == 'NEXT_IS_HOST':
                if len(args) >= 2:
                    host = args[1]
                if len(args) == 3:
                    port = args[2]
                else:
                    port = 21
                if user == None:
                    state = 'NEXT_IS_USER'
                else:
                    state = 'NEXT_IS_SOMETHING'

            elif state == 'NEXT_IS_USER':
                if len(args) == 1:
                    user = args[0]
                    if user != 'anonymous':
                        state = 'NEXT_IS_PASS'
                    else:
                        state = 'NEXT_IS_SOMETHING'

            elif state == 'NEXT_IS_PASS':
                if len(args) == 1:
                    passwd = args[0]
                    state = 'NEXT_IS_SOMETHING'

            elif state == 'NEXT_IS_FILE':
                if len(args) == 1:
                    dfile = args[0]
                    state = 'NEXT_IS_SOMETHING'
                    i = incident("dionaea.download.offer")
                    if isinstance(self, connection):
                        i.con = self
                    elif hasattr(self, 'con') and isinstance(self.con, connection):
                        i.con = self.con
                    i.ftpmode = ftpmode
                    i.url = "ftp://%s:%s@%s:%i/%s" % (user,
                                                      passwd,host,port,dfile)
                    i.report()

            elif state == 'NEXT_IS_PATH':
                if len(args) == 1:
                    fpath = args[0]
                    state = 'NEXT_IS_SOMETHING'
        logger.info("ftp://%s:%s@%s:%i/%s/%s" %
                    (user,passwd,host,port,fpath,dfile))
        return out,None

    def cmd_TFTP(self, args):
        logger.debug("TFTP %s" % (args) )
        if len(args) != 4:
            logger.debug("invalid number of args")
            return "foo","error, invalid number of args"
        if args[0] == '-i' and args[2].lower() == 'get':
            host = args[1]
            file = args[3]
#            logger.debug("TFTP %s %s" % (host, file))
            i = incident("dionaea.download.offer")
            url = 'tftp://' + host + '/' + file
            i.url = url
            if isinstance(self, connection):
                i.con = self
            elif hasattr(self, 'con') and isinstance(self.con, connection):
                i.con = self.con
            i.report()
            return "downloading",None
        return None,None

    def cmd_CMD(self, args):
        for i in range(len(args)):
            if args[i] == '/c' or args[i] == '/k':
                line = " ".join(args[i+1:])
                line = line.encode('UTF-8')
                cmd,args,redir = self.parse(line)
                out,err = self.execute(cmd,args)
                return out,err


        return None,None

    def parse(self, line):
        args = []
        cmd = None
        redir = None
        line = line.strip()

        if len(line) == 0:
            return cmd,args,redir

        end = line[len(line)-1]
        if end == ord('&') or end == ord(';') or end == ord('\n'):
            line = line[:len(line)-1]
        cmd = line
        i=0
        for i in range(len(line)):
            if line[i] == ord(' '):
                cmd = line[:i]
                line = line[i:]
                break
        argstr = line

        if cmd != None:
            cmd = cmd.decode()

        escape = False
        for i in range(len(line)):
            if line[i] == ord('^'):
                if escape == False:
                    escape == True
                else:
                    escape == False
            elif ( line[i] == ord('>') and escape == False):
                argstr = line[:i]
                redir = line[i:]
                break

        args = argstr.decode().split()

        return cmd,args,redir

    def line(self, data, eof=False):
        if type(data) == str:
            data = data.encode()

        escape = False
        for i in range(len(data)):
            if int(data[i]) == ord('^'):
                if escape == False:
                    escape == True
                else:
                    escape == False
            elif ( (data[i] == ord(';') and escape == False)
                    or data[i] == ord('&')
                    or data[i] == ord('\0')
                    or data[i] == ord('\n')):
                j=i+1
                while j < len(data) and data[j] == ord('&'):
                    j=j+1
                line = data[:i]
                data = data[j:]
                if i+1 == len(data):
                    return data,line,False
                else:
                    return data,line,True

        if eof:
            line = data[:i]
            data = data[i:]
            return data,line,False

        return data,b'',False

    def void(self, data):
        pass


class remoteshell(cmdexe,connection):
    def __init__(self, con=None):
        connection.__init__(self,'tcp')
        cmdexe.__init__(self, self.send)
        self.timeouts.listen = 10
        self.timeouts.connecting = 5
        self.timeouts.idle = 1
        self.timeouts.sustain = 15
        self._in.accounting.limit = 1024

    def handle_established(self):
        self.send(
            "Microsoft Windows 2000 [Version 5.00.2195]\n(C) Copyright 1985-2000 Microsoft Corp.\n\nC:\\WINDOWS\\System32>")

    def handle_disconnect(self):
        return False

    def handle_error(self, err):
        pass

    def handle_timeout_idle (self):
        self.send("\n")
        return True

    def handle_timeout_listen (self):
        #        if hasattr(self,'con') and self.con:
        #            self.con.unref()
        return False

    def handle_timeout_sustain(self):
        return False

    def handle_origin(self, parent):
        pass


class cmdshellhandler(ihandler):

    def __init__(self, path, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)

    def handle_incident(self, icd):
        logger.debug("do shell")
        con = icd.con
        c = remoteshell()
        i = incident("dionaea.connection.link")
        i.parent = icd.con
        i.child = c
        if icd.origin == "dionaea.service.shell.listen":
            if c.bind(con.local.host,icd.get('port')) == True and c.listen() == True:
                i.report()
            else:
                c.close()
#                con.unref()
        elif icd.origin == "dionaea.service.shell.connect":
            c.bind(con.local.host,0)
            c.connect(icd.get('host'), icd.get('port'))
            i.report()
        else:
            c.close()
