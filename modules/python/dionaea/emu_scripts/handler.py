# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import re

logger = logging.getLogger("emu_scripts")


class BaseHandler(object):
    name = ""

    def __init__(self, config=None):
        self._config = {}
        if isinstance(config, dict):
            self._config = config

        self.min_match_count = 0
        self._regex_detect = []

        self._regex_url = re.compile(
            r"(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
        )

    def run(self, data):
        match_count = 0
        for regex in self._regex_detect:
            m = regex.search(data)
            if m:
                match_count += 1

        if match_count < self.min_match_count:
            logger.info("Match count for %s is %d should at least be %d", self.name, match_count, self.min_match_count)
            return

        logger.info("Looking for URLs '%s'", self.name)
        urls = []
        for m in self._regex_url.finditer(data):
            urls.append(m.group("url"))
        return urls


class RawURL(object):
    name = "raw_url"

    def __init__(self, config=None):
        self._config = {}
        if isinstance(config, dict):
            self._config = config

        self._regex_url = re.compile(
            r"(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
        )

    def run(self, data):
        urls = []
        for m in self._regex_url.finditer(data):
            urls.append(m.group("url"))
        return urls


class PowerShell(BaseHandler):
    name = "powershell"

    def __init__(self, config=None):
        BaseHandler.__init__(self, config=config)

        self.min_match_count = 2
        self._regex_detect = [
            re.compile(r"New-Object\s+System\.Net\.WebClient"),
            re.compile(r"DownloadFile([^,]+?,[^,]+?)"),
            re.compile(r"Invoke-Expression([^)]+?)")
        ]

        self._regex_url = re.compile(
            r"\w+\s*=\s*\"\s*(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)\s*\""
        )


class VBScript(BaseHandler):
    name = "vbscript"

    def __init__(self, config=None):
        BaseHandler.__init__(self, config=config)

        self.min_match_count = 1
        self._regex_detect = [
            re.compile(r"Set\s+\w+\s+=\s+CreateObject\(.*?(Msxml2.XMLHTTP|Wscript.Shell).*?\)")
        ]

        self._regex_url = re.compile(
            r"\.Open\s+\"GET\"\s*,\s*\"(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)\""
        )
