# Copyright (C) 2015-2016 KillerInstinct
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from CAPEsolo.capelib.signatures import Signature


class NetworkActivity(Signature):
    name = "network_activity"
    description = "Network activity occurred during the analysis"
    severity = 2
    categories = ["network"]
    authors = ["Enzok"]
    minimum = "1.0"
    evented = True

    filter_apinames = set(
        [
            "getaddrinfo",
            "InternetConnectA",
            "InternetConnectW",
            "connect",
            "send",
            "WSAConnect",
            "GetAddrInfoW",
            "InternetCrackUrlA",
            "GetAddrInfoExW",
            "ConnectEx",
        ]
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.nodes = []
        self.names = []
        self.inet_connect = []
        self.connect = []
        self.send = []
        self.wsa_connect = []
        self.urls = []

    def on_call(self, call, process):
        if call["api"] == "getaddrinfo" or call["api"] == "GetAddrInfoW":
            self.nodes.append(
                {call["api"]: {"node": self.get_argument(call, "NodeName")}}
            )

        elif call["api"] == "GetAddrInfoExW":
            self.nodes.append(
                {call["api"]: {"node": self.get_argument(call, "Name")}}
            )

        elif call["api"] == "InternetCrackUrlA":
            self.urls.append(
                {call["api"]: {"node": self.get_argument(call, "Url")}}
            )

        elif call["api"].startswith("InternetConnect"):
            self.inet_connect.append(
                {call["api"]: {"ServerName": self.get_argument(call, "ServerName")}}
            )

        elif call["api"] == "connect" or call["api"] == "ConnectEx":
            ip = self.get_argument(call, "ip")
            port = self.get_argument(call, "port")
            socket = self.get_argument(call, "socket")
            self.connect.append(
                {call["api"]: {"ip": ip, "port": port, "socket": socket}}
            )

        elif call["api"] == "send":
            self.send.append(
                {call["api"]: {"socket": self.get_argument(call, "socket")}}
            )

        elif call["api"] == "WSAConnect":
            self.wsa_connect.append(
                {call["api"]: {"ip": self.get_argument(call, "ip")}}
            )

    def on_complete(self):
        ret = False

        if self.nodes:
            for item in self.nodes:
                self.data.append(item)

        if self.names:
            for item in self.names:
                self.data.append(item)

        if self.inet_connect:
            for item in self.inet_connect:
                self.data.append(item)

        if self.urls:
            for item in self.urls:
                self.data.append(item)

        if self.connect:
            for item in self.connect:
                self.data.append(item)

        if self.send:
            for item in self.send:
                self.data.append(item)

        if self.wsa_connect:
            for item in self.wsa_connect:
                self.data.append(item)

        if self.data:
            ret = True

        return ret
