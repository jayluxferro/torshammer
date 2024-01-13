"""SocksiPy - Python SOCKS module.
Version 1.00

Copyright 2006 Dan-Haim. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Dan Haim nor the names of his contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY DAN HAIM "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
EVENT SHALL DAN HAIM OR HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMANGE.


This module provides a standard socket-like interface for Python
for tunneling connections through SOCKS proxies.

"""

import socket
import struct

PROXY_TYPE_SOCKS4 = 1
PROXY_TYPE_SOCKS5 = 2
PROXY_TYPE_HTTP = 3

_defaultProxy = None
_orgSocket = socket.socket


class ProxyError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class GeneralProxyError(ProxyError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Socks5AuthError(ProxyError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Socks5Error(ProxyError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Socks4Error(ProxyError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class HTTPError(ProxyError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


_generalErrors = ("success",
                  "invalid data",
                  "not connected",
                  "not available",
                  "bad proxy type",
                  "bad input")

_socks5Errors = ("succeeded",
                 "general SOCKS server failure",
                 "connection not allowed by ruleset",
                 "Network unreachable",
                 "Host unreachable",
                 "Connection refused",
                 "TTL expired",
                 "Command not supported",
                 "Address type not supported",
                 "Unknown error")

_socks5AuthErrors = ("succeeded",
                     "authentication is required",
                     "all offered authentication methods were rejected",
                     "unknown username or invalid password",
                     "unknown error")

_socks4Errors = ("request granted",
                 "request rejected or failed",
                 "request rejected because SOCKS server cannot connect to identd on the client",
                 "request rejected because the client program and identd report different user-ids",
                 "unknown error")


def setDefaultProxy(proxyType=None, addr=None, port=None, rdns=True, username=None, password=None):
    """setDefaultProxy(proxyType, addr[, port[, rdns[, username[, password]]]])
    Sets a default proxy which all further sockSocket objects will use,
    unless explicitly changed.
    """
    global _defaultProxy
    _defaultProxy = (proxyType, addr, port, rdns, username, password)


class sockSocket(socket.socket):
    """sockSocket([family[, type[, proto]]]) -> socket object

    Open a SOCKS enabled socket. The parameters are the same as
    those of the standard socket init. In order for SOCKS to work,
    you must specify family=AF_INET, type=SOCK_STREAM and proto=0.
    """

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, _sock=None):
        _orgSocket.__init__(self, family, type, proto, _sock)
        if _defaultProxy is not None:
            self.__proxy = _defaultProxy
        else:
            self.__proxy = (None, None, None, None, None, None)
        self.__proxySockName = None
        self.__proxyPeerName = None

    def __recvAll(self, bytes):
        """__recvAll(bytes) -> data
        Receive EXACTLY the number of bytes requested from the socket.
        Blocks until the required number of bytes have been received.
        """
        data = ""
        while len(data) < bytes:
            data = data + self.recv(bytes - len(data))
        return data

    def setProxy(self, proxyType=None, addr=None, port=None, rdns=True, username=None, password=None):
        """setProxy(proxyType, addr[, port[, rdns[, username[, password]]]])
        Sets the proxy to be used.
        proxyType -	The type of the proxy to be used. Three types
                are supported: PROXY_TYPE_SOCKS4 (including socks4a),
                PROXY_TYPE_SOCKS5 and PROXY_TYPE_HTTP
        addr -		The address of the server (IP or DNS).
        port -		The port of the server. Defaults to 1080 for SOCKS
                servers and 8080 for HTTP proxy servers.
        rdns -		Should DNS queries be preformed on the remote side
                (rather than the local side). The default is True.
                Note: This has no effect with SOCKS4 servers.
        username -	Username to authenticate with to the server.
                The default is no authentication.
        password -	Password to authenticate with to the server.
                Only relevant when username is also provided.
        """
        self.__proxy = (proxyType, addr, port, rdns, username, password)

    def __negotiateSocks5(self, destAddr, destPort):
        """__negotiateSocks5(self,destAddr,destPort)
        Negotiates a connection through a SOCKS5 server.
        """
        # First we'll send the authentication packages we support.
        if (self.__proxy[4] is not None) and (self.__proxy[5] is not None):
            # The username/password details were supplied to the
            # setProxy method so we support the USERNAME/PASSWORD
            # authentication (in addition to the standard none).
            self.sendall("\x05\x02\x00\x02")
        else:
            # No username/password were entered, therefore we
            # only support connections with no authentication.
            self.sendall("\x05\x01\x00")
        # We'll receive the server's response to determine which
        # method was selected
        chosenAuth = self.__recvAll(2)
        if chosenAuth[0] != "\x05":
            self.close()
            raise GeneralProxyError((1, _generalErrors[1]))
        # Check the chosen authentication method
        if chosenAuth[1] == "\x00":
            # No authentication is required
            pass
        elif chosenAuth[1] == "\x02":
            # Okay, we need to perform a basic username/password
            # authentication.
            self.sendall(
                "\x01" + chr(len(self.__proxy[4])) + self.__proxy[4] + chr(len(self.proxy[5])) + self.__proxy[5])
            authStat = self.__recvAll(2)
            if authStat[0] != "\x01":
                # Bad response
                self.close()
                raise GeneralProxyError((1, _generalErrors[1]))
            if authStat[1] != "\x00":
                # Authentication failed
                self.close()
                raise Socks5AuthError((3, _socks5AuthErrors[3]))
        # Authentication succeeded
        else:
            # Reaching here is always bad
            self.close()
            if chosenAuth[1] == "\xFF":
                raise Socks5AuthError((2, _socks5AuthErrors[2]))
            else:
                raise GeneralProxyError((1, _generalErrors[1]))
        # Now we can request the actual connection
        req = "\x05\x01\x00"
        # If the given destination address is an IP address, we'll
        # use the IPv4 address request even if remote resolving was specified.
        try:
            ipaddr = socket.inet_aton(destAddr)
            req = req + "\x01" + ipaddr
        except socket.error:
            # Well it's not an IP number,  so it's probably a DNS name.
            if self.__proxy[3]:
                # Resolve remotely
                ipaddr = None
                req = req + "\x03" + chr(len(destAddr)) + destAddr
            else:
                # Resolve locally
                ipaddr = socket.inet_aton(socket.gethostbyname(destAddr))
                req = req + "\x01" + ipaddr
        req = req + struct.pack(">H", destPort)
        self.sendall(req)
        # Get the response
        resp = self.__recvAll(4)
        if resp[0] != "\x05":
            self.close()
            raise GeneralProxyError((1, _generalErrors[1]))
        elif resp[1] != "\x00":
            # Connection failed
            self.close()
            if ord(resp[1]) <= 8:
                raise Socks5Error(ord(resp[1]), _generalErrors[ord(resp[1])])
            else:
                raise Socks5Error(9, _generalErrors[9])
        # Get the bound address/port
        elif resp[3] == "\x01":
            boundAddr = self.__recvAll(4)
        elif resp[3] == "\x03":
            resp = resp + self.recv(1)
            boundAddr = self.__recvAll(resp[4])
        else:
            self.close()
            raise GeneralProxyError((1, _generalErrors[1]))
        boundPort = struct.unpack(">H", self.__recvAll(2))[0]
        self.__proxySockName = (boundAddr, boundPort)
        if ipaddr is not None:
            self.__proxyPeerName = (socket.inet_ntoa(ipaddr), destPort)
        else:
            self.__proxyPeerName = (destAddr, destPort)

    def getProxySockName(self):
        """getProxySockName() -> address info
        Returns the bound IP address and port number at the proxy.
        """
        return self.__proxySockName

    def getProxyPeerName(self):
        """getProxyPeerName() -> address info
        Returns the IP and port number of the proxy.
        """
        return _orgSocket.getpeername(self)

    def getPeerName(self):
        """getPeerName() -> address info
        Returns the IP address and port number of the destination
        machine (note: getProxyPeerName returns the proxy)
        """
        return self.__proxyPeerName

    def __negotiateSocks4(self, destAddr, destPort):
        """__negotiateSocks4(self,destAddr,destPort)
        Negotiates a connection through a SOCKS4 server.
        """
        # Check if the destination address provided is an IP address
        rmtrslv = False
        try:
            ipaddr = socket.inet_aton(destAddr)
        except socket.error:
            # It's a DNS name. Check where it should be resolved.
            if self.__proxy[3]:
                ipaddr = "\x00\x00\x00\x01"
                rmtrslv = True
            else:
                ipaddr = socket.inet_aton(socket.gethostbyname(destAddr))
        # Construct the request packet
        req = "\x04\x01" + struct.pack(">H", destPort) + ipaddr
        # The username parameter is considered userid for SOCKS4
        if self.__proxy[4] is not None:
            req = req + self.__proxy[4]
        req = req + "\x00"
        # DNS name if remote resolving is required
        # NOTE: This is actually an extension to the SOCKS4 protocol
        # called SOCKS4A and may not be supported in all cases.
        if rmtrslv:
            req = req + destAddr + "\x00"
        self.sendall(req)
        # Get the response from the server
        resp = self.__recvAll(8)
        if resp[0] != "\x00":
            # Bad data
            self.close()
            raise GeneralProxyError((1, _generalErrors[1]))
        if resp[1] != "\x5A":
            # Server returned an error
            self.close()
            if ord(resp[1]) in (91, 92, 93):
                self.close()
                raise Socks4Error((ord(resp[1]), _socks4Errors[ord(resp[1]) - 90]))
            else:
                raise Socks4Error((94, _socks4Errors[4]))
        # Get the bound address/port
        self.__proxySockName = (socket.inet_ntoa(resp[4:]), struct.unpack(">H", resp[2:4])[0])
        if rmtrslv is not None:
            self.__proxyPeerName = (socket.inet_ntoa(ipaddr), destPort)
        else:
            self.__proxyPeerName = (destAddr, destPort)

    def __negotiateHTTP(self, destAddr, destPort):
        """__negotiateHTTP(self,destAddr,destPort)
        Negotiates a connection through an HTTP server.
        """
        # If we need to resolve locally, we do this now
        if not self.__proxy[3]:
            addr = socket.gethostbyname(destAddr)
        else:
            addr = destAddr
        self.sendall("CONNECT " + addr + ":" + str(destPort) + " HTTP/1.1\r\n" + "Host: " + destAddr + "\r\n\r\n")
        # We read the response until we get the string "\r\n\r\n"
        resp = self.recv(1)
        while resp.find("\r\n\r\n") == -1:
            resp = resp + self.recv(1)
        # We just need the first line to check if the connection
        # was successful
        statusLine = resp.splitlines()[0].split(" ", 2)
        if statusLine[0] not in ("HTTP/1.0", "HTTP/1.1"):
            self.close()
            raise GeneralProxyError((1, _generalErrors[1]))
        try:
            statuscode = int(statusLine[1])
        except ValueError:
            self.close()
            raise GeneralProxyError((1, _generalErrors[1]))
        if statuscode != 200:
            self.close()
            raise HTTPError((statuscode, statusLine[2]))
        self.__proxySockName = ("0.0.0.0", 0)
        self.__proxyPeerName = (addr, destPort)

    def connect(self, destPair):
        """connect(self,despair)
        Connects to the specified destination through a proxy.
        destPair - A tuple of the IP/DNS address and the port number.
        (identical to socket's connect).
        To select the proxy server use setproxy().
        """
        # Do a minimal input check first
        if (type(destPair) in (list, tuple) == False) or (len(destPair) < 2) or (type(destPair[0]) != str) or (
                type(destPair[1]) != int):
            raise GeneralProxyError((5, _generalErrors[5]))
        if self.__proxy[0] == PROXY_TYPE_SOCKS5:
            if self.__proxy[2] is not None:
                portNum = self.__proxy[2]
            else:
                portNum = 1080
            _orgSocket.connect(self, (self.__proxy[1], portNum))
            self.__negotiateSocks5(destPair[0], destPair[1])
        elif self.__proxy[0] == PROXY_TYPE_SOCKS4:
            if self.__proxy[2] is not None:
                portNum = self.__proxy[2]
            else:
                portNum = 1080
            _orgSocket.connect(self, (self.__proxy[1], portNum))
            self.__negotiateSocks4(destPair[0], destPair[1])
        elif self.__proxy[0] == PROXY_TYPE_HTTP:
            if self.__proxy[2] is not None:
                portNum = self.__proxy[2]
            else:
                portNum = 8080
            _orgSocket.connect(self, (self.__proxy[1], portNum))
            self.__negotiateHTTP(destPair[0], destPair[1])
        elif self.__proxy[0] is None:
            _orgSocket.connect(self, (destPair[0], destPair[1]))
        else:
            raise GeneralProxyError((4, _generalErrors[4]))
