# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2010  Mark Schloesser
# SPDX-FileCopyrightText: 2009  Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

import hashlib
import logging
import re


logger = logging.getLogger("util")
logger.setLevel(logging.DEBUG)


def md5file(filename):
    """
    Compute md5 checksum of file.

    :param str filename: File to read
    :return: MD5 checksum as hex string
    :rtype: str
    """
    return hashfile(filename, hashlib.md5())


def sha512file(filename):
    """
    Compute sha512 checksum of file.

    :param str filename: File to read
    :return: SHA512 checksum as hex string
    :rtype: str
    """
    return hashfile(filename, hashlib.sha512())

def sha256file(filename):
    """
    Compute sha256 checksum of file.

    :param str filename: File to read
    :return: SHA256 checksum as hex string
    :rtype: str
    """
    return hashfile(filename, hashlib.sha256())

def hashfile(filename, digest):
    """
    Computer checksum of file.

    :param str filename: File to read
    :param _hashlib.Hash digest: Hash object
    :return: Checksum as hex string
    :rtype: str
    """
    fh = open(filename, mode="rb")
    while 1:
        buf = fh.read(4096)
        if len(buf) == 0:
            break
        digest.update(buf)
    fh.close()
    return digest.hexdigest()


def detect_shellshock(connection, data, report_incidents=True):
    """
    Try to find Shellshock attacks, included download commands and URLs.

    :param connection: The connection object
    :param data: Data to analyse
    :param report_incidents:
    :return: List of urls or None
    """
    from dionaea.core import incident
    regex = re.compile(r"\(\)\s*\t*\{.*;\s*\}\s*;")
    if not regex.search(data):
        return None
    logger.debug("Shellshock attack found")

    urls = []
    regex = re.compile(
        r"(wget|curl).+(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
    )
    for m in regex.finditer(data):
        logger.debug("Found download command with url %s", m.group("url"))
        urls.append(m.group("url"))
        if report_incidents:
            i = incident("dionaea.download.offer")
            i.con = connection
            i.url = m.group("url")
            i.report()

    return urls


def find_shell_download(connection, data, report_incidents=True):
    """
    Try to analyse the data and find download commands

    :param connection: The connection object
    :param data: Data to analyse
    :param report_incidents:
    :return: List of urls or None
    """
    from dionaea.core import incident
    urls = []
    regex = re.compile(
        r"(wget|curl).+(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
    )
    for m in regex.finditer(data):
        logger.debug("Found download command with url %s", m.group("url"))
        urls.append(m.group("url"))
        if report_incidents:
            i = incident("dionaea.download.offer")
            i.con = connection
            i.url = m.group("url")
            i.report()

    return urls

def xor(data, key):
    l = len(key)
    return bytearray((
        (data[i] ^ key[i % l]) for i in range(0, len(data))
    ))

def calculate_doublepulsar_opcode(t):
    op = (t) + (t >> 8) + (t >> 16) + (t >> 24)
    return op
