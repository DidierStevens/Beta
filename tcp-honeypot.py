#!/usr/bin/env python

__description__ = 'TCP honeypot'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2018/03/17'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2018/03/08: start
  2018/03/09: continue
  2018/03/17: continue, added ssl

Todo:
"""

THP_REFERENCE = 'reference'
THP_SSL = 'ssl'
THP_CERTFILE = 'certfile'
THP_KEYFILE = 'keyfile'
THP_SSLCONTEXT = 'sslcontext'
THP_BANNER = 'banner'
THP_REPLY = 'reply'
THP_MATCH = 'match'
THP_LOOP = 'loop'
THP_REGEX = 'regex'
THP_ACTION = 'action'
THP_DISCONNECT = 'disconnect'

#Terminate With CR LF
def TW_CRLF(data):
    if isinstance(data, str):
        data = [data]
    return '\r\n'.join(data + [''])

dListeners = {
    22:    {THP_BANNER: TW_CRLF('SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2')},
    443:   {THP_SSL: {THP_CERTFILE: 'cert-20180317-161753.crt', THP_KEYFILE: 'key-20180317-161753.pem'},
            THP_REPLY: TW_CRLF(['HTTP/1.1 200 OK', 'Date: %TIME_GMT_RFC2822%', 'Server: Apache', 'Last-Modified: Wed, 06 Jul 2016 17:51:03 GMT', 'ETag: "59652-cfd-edc33a50bfec6"', 'Accept-Ranges: bytes', 'Content-Length: 285', 'Connection: close', 'Content-Type: text/html; charset=UTF-8', '', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">', '<link rel="icon" type="image/png" href="favicon.png"/>', '<html>', ' <head>', '    <title>Home</title>', '   <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">', '  </head>', ' <body>Welcome home!</body>', '</html>'])
           },
    8443:  {THP_REFERENCE: 443},
    80:    {THP_REPLY: TW_CRLF(['HTTP/1.1 200 OK', 'Date: %TIME_GMT_RFC2822%', 'Server: Apache', 'Last-Modified: Wed, 06 Jul 2016 17:51:03 GMT', 'ETag: "59652-cfd-edc33a50bfec6"', 'Accept-Ranges: bytes', 'Content-Length: 285', 'Connection: close', 'Content-Type: text/html; charset=UTF-8', '', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">', '<link rel="icon" type="image/png" href="favicon.png"/>', '<html>', ' <head>', '    <title>Home</title>', '   <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">', '  </head>', ' <body>Welcome home!</body>', '</html>'])},
    591:   {THP_REFERENCE: 80},
    8008:  {THP_REFERENCE: 80},
    8080:  {THP_REFERENCE: 80},
    25:    {THP_LOOP: 10,
            THP_BANNER: TW_CRLF('220 HP1EUR02TC012.mail.protection.outlook.com Microsoft ESMTP MAIL Service ready at %TIME_GMT_RFC2822%'),
            THP_MATCH: {
                      'EHLO':    {THP_REGEX: '^[Ee][Hh][Ll][Oo]',   THP_REPLY: TW_CRLF(['250-HP1EUR02TC012.mail.protection.outlook.com', '250-PIPELINING', '250-SIZE 20971520', '250-ETRN', '250-ENHANCEDSTATUSCODES', '250 8BITMIME'])},
                      'default': {THP_REGEX: '^.',     THP_REPLY: TW_CRLF('500 5.5.2 Error: bad syntax')},
                     }
           },
    11211: {THP_LOOP: 10,
            THP_MATCH: {
                      'stats':   {THP_REGEX: '^stats',   THP_REPLY: TW_CRLF(['STAT pid 14868', 'STAT uptime 175931', 'STAT time %TIME_GMT_EPOCH%', 'STAT version 1.5.4', 'STAT id C3B806AA71F0887773210E75DD12BDAD', 'STAT pointer_size 32', 'STAT rusage_user 620.299700', 'STAT rusage_system 1545.703017', 'STAT curr_items 228', 'STAT total_items 779', 'STAT bytes 15525', 'STAT curr_connections 92', 'STAT total_connections 1740', 'STAT connection_structures 165', 'STAT cmd_get 7411', 'STAT cmd_set 28445156', 'STAT get_hits 5183', 'STAT get_misses 2228', 'STAT evictions 0', 'STAT bytes_read 2112768087', 'STAT bytes_written 1000038245', 'STAT limit_maxbytes 52428800', 'STAT threads 1', 'END'])},
                      'version': {THP_REGEX: '^version', THP_REPLY: TW_CRLF('VERSION 1.5.4')},
                      'get':     {THP_REGEX: '^get ',    THP_REPLY: TW_CRLF(['VALUE a 0 2', 'AA', 'END'])},
                      'set':     {THP_REGEX: '^set ',    THP_REPLY: TW_CRLF('STORED')},
                      'quit':    {THP_REGEX: '^quit',    THP_ACTION: THP_DISCONNECT},
                     }
           },
    21:    {THP_LOOP: 10,
            THP_BANNER: TW_CRLF('220 FTP server ready. All transfers are logged. (FTP) [no EPSV]'),
            THP_MATCH: {
                      'user':   {THP_REGEX: '^USER ',    THP_REPLY: TW_CRLF('331 Please specify the password.')},
                      'pass':   {THP_REGEX: '^PASS ',    THP_REPLY: TW_CRLF('230 Login successful.')},
                      'typea':  {THP_REGEX: '^TYPE A',   THP_REPLY: TW_CRLF('200 Switching to ASCII mode.')},
                      'auth':   {THP_REGEX: '^AUTH',     THP_REPLY: TW_CRLF('530 Please login with USER and PASS.')},
                      'help':   {THP_REGEX: '^HELP',     THP_REPLY: TW_CRLF(['220 FTP server ready. All transfers are logged. (FTP) [no EPSV]', '530 Please login with USER and PASS.'])},
                     }
           },
}

import optparse
import socket
import select
import threading
import time
import re
import ssl
import textwrap

def PrintManual():
    manual = r'''
Manual:

TCP listeners are configured with Python dictionary dListeners. The key is the port number (integer) and the value is another dictionary (listener dictionary).

When this listener dictionary is empty, the honeypot will accept TCP connections on the configured port, perform a single read and then close the connection.
The listener can be configured to perform more than one read: add key THP_LOOP to the dictionary with an integer as value. The integer specifies the maximum number of reads.
A banner can be transmitted before the first read, this is done by adding key THP_BANNER to the dictionary with a string as the value (the banner).
The listener can be configured to send a reply after each read, this is done by adding key THP_REPLY to the dictionary with a string as the value (the reply).
To increase the interactivity of the honeypot, keywords can be defined with replies. This is done by adding a new dictionary to the dictionary with key THP_MATCH.
Entries in this match dictionary are regular expressions (THP_REGEX): when a regular expression matches read data, the corresponding reply is send or action performed (e.g. disconnect).

A listener can be configured to accept SSL/TLS connections by adding key THP_SSL to the listener dictionary with a dictionary as value specifying the certificate (THP_CERTFILE) and key (THP_KEYFILE) to use. If an SSL context can not be created (for example because of missing certificate file), the listener will fallback to TCP.

When several ports need to behave the same, the dictionary can just contain a reference (THP_REFERENCE) to the port which contains the detailed description.

Helper function TW_CRLF (Terminate With CR/LF) can be used to format replies and banners.
Replies and banners can contain aliases: %TIME_GMT_RFC2822% and %TIME_GMT_EPOCH%, they will be instantiated when a reply is transmitted.

Output is written to stdout and a log file.

This tool has several command-line options, but it does not take arguments.

It is written for Python 2.7 and was tested on Windows 10, Ubuntu 16 and CentOS 6.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 Integer If Python 2
def C2IIP2(data):
    if sys.version_info[0] > 2:
        return data
    else:
        return ord(data)

# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

def FormatTime(epoch=None):
    if epoch == None:
        epoch = time.time()
    return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

class cOutput():
    def __init__(self, filename=None, bothoutputs=False):
        self.filename = filename
        self.bothoutputs = bothoutputs
        if self.filename and self.filename != '':
            self.f = open(self.filename, 'w')
        else:
            self.f = None

    def Line(self, line):
        if not self.f or self.bothoutputs:
            print(line)
        if self.f:
            try:
                self.f.write(line + '\n')
                self.f.flush()
            except:
                pass

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (FormatTime(), line))

    def Close(self):
        if self.f:
            self.f.close()
            self.f = None

def ReplaceAliases(data):
    data = data.replace('%TIME_GMT_RFC2822%', time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime()))
    data = data.replace('%TIME_GMT_EPOCH%', str(int(time.time())))
    return data

def ParseNumber(number):
    if number.startswith('0x'):
        return int(number[2:], 16)
    else:
        return int(number)

def MyRange(begin, end):
    if begin < end:
        return range(begin, end + 1)
    elif begin == end:
        return [begin]
    else:
        return range(begin, end - 1, -1)

def ParsePorts(expression):
    ports = []
    for portrange in expression.split(','):
        result = portrange.split('-')
        if len(result) == 1:
            ports.append(ParseNumber(result[0]))
        else:
            ports.extend(MyRange(ParseNumber(result[0]), ParseNumber(result[1])))
    return ports

class ConnectionThread(threading.Thread):
    global dListeners

    def __init__(self, oSocket, oOutput, options):
        threading.Thread.__init__(self)
        self.oSocket = oSocket
        self.oOutput = oOutput
        self.options = options

    def run(self):
        oSocketConnection, address = self.oSocket.accept()
        connectionID = '%s:%d-%s:%d' % (self.oSocket.getsockname() + address)
        oSocketConnection.settimeout(self.options.timeout)
        dListener = dListeners[self.oSocket.getsockname()[1]]
        if THP_REFERENCE in dListener:
            dListener = dListeners[dListener[THP_REFERENCE]]
        try:
            oSSLConnection = None
            oSSLContext = dListener.get(THP_SSLCONTEXT, None)
            if oSSLContext == None:
                connection = oSocketConnection
            else:
                oSSLConnection = oSSLContext.wrap_socket(oSocketConnection, server_side=True)
                connection = oSSLConnection
            self.oOutput.LineTimestamped('%s connection' % connectionID)
            if THP_BANNER in dListener:
                connection.send(ReplaceAliases(dListener[THP_BANNER]))
                self.oOutput.LineTimestamped('%s send banner' % connectionID)
            for i in range(0, dListener.get(THP_LOOP, 1)):
                data = connection.recv(self.options.readbuffer)
                self.oOutput.LineTimestamped('%s data %s' % (connectionID, repr(data)))
                if THP_REPLY in dListener:
                    connection.send(ReplaceAliases(dListener[THP_REPLY]))
                    self.oOutput.LineTimestamped('%s send reply' % connectionID)
                if THP_MATCH in dListener:
                    matchLongest = -1
                    dMatchLongest = None
                    matchnameLongest = None
                    for matchname, dMatch in dListener[THP_MATCH].items():
                        oMatch = re.match(dMatch[THP_REGEX], data)
                        if oMatch != None and len(oMatch.group()) > matchLongest:
                            dMatchLongest = dMatch
                            matchLongest = len(oMatch.group())
                            matchnameLongest = matchname
                    if dMatchLongest != None:
                        if THP_REPLY in dMatchLongest:
                            connection.send(ReplaceAliases(dMatchLongest[THP_REPLY]))
                            self.oOutput.LineTimestamped('%s send %s reply' % (connectionID, matchnameLongest))
                        if dMatchLongest.get(THP_ACTION, '') == THP_DISCONNECT:
                            self.oOutput.LineTimestamped('%s disconnecting' % connectionID)
                            break
        except socket.timeout:
            self.oOutput.LineTimestamped('%s timeout' % connectionID)
        except Exception as e:
            self.oOutput.LineTimestamped('%s %s' % (connectionID, str(e)))
        #a# is it necessary to close both oSSLConnection and oSocketConnection?
        if oSSLConnection != None:
            oSSLConnection.shutdown(socket.SHUT_RDWR)
            oSSLConnection.close()
        oSocketConnection.shutdown(socket.SHUT_RDWR)
        oSocketConnection.close()
        self.oOutput.LineTimestamped('%s closed' % connectionID)

def TCPHoneypot(options):
    global dListeners

    oOutput = cOutput('tcp-honeypot-%s.log' % FormatTime(), True)

    if options.ports != '':
        oOutput.LineTimestamped('Ports specified via command-line option: %s' % options.ports)
        dListeners = {}
        for port in ParsePorts(options.ports):
            dListeners[port] = {}

    if options.extraports != '':
        oOutput.LineTimestamped('Extra ports: %s' % options.extraports)
        for port in ParsePorts(options.extraports):
            dListeners[port] = {}

    sockets = []

    for port in dListeners.keys():
        oSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        oSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            oSocket.bind((options.address, port))
        except socket.error as e:
            if '[Errno 98] Address already in use' in str(e):
                oOutput.LineTimestamped('Port %d can not be used, it is already open' % port)
                continue
            elif '[Errno 99] Cannot assign requested address' in str(e) or '[Errno 10049] The requested address is not valid in its context' in str(e):
                oOutput.LineTimestamped('Address %s can not be used (port %d)' % (options.address, port))
                continue
            elif '[Errno 10013] An attempt was made to access a socket in a way forbidden by its access permissions' in str(e):
                oOutput.LineTimestamped('Port %d can not be used, access is forbidden' % port)
                continue
            else:
                raise e
        oSocket.listen(5)
        oOutput.LineTimestamped('Listening on %s %d' % oSocket.getsockname())
        sockets.append(oSocket)
        if THP_SSL in dListeners[port]:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            try:
                context.load_cert_chain(certfile=dListeners[port][THP_SSL][THP_CERTFILE], keyfile=dListeners[port][THP_SSL][THP_KEYFILE])
                dListeners[port][THP_SSLCONTEXT] = context
                oOutput.LineTimestamped('Created SSL context for %s %d' % oSocket.getsockname())
            except IOError as e:
                if '[Errno 2]' in str(e):
                    oOutput.LineTimestamped('Error reading certificate and/or key file: %s %s' % (dListeners[port][THP_SSL][THP_CERTFILE], dListeners[port][THP_SSL][THP_KEYFILE]))
                else:
                    oOutput.LineTimestamped('Error creating SSL context: %s' % e)
                oOutput.LineTimestamped('SSL not enabled for %s %d' % oSocket.getsockname())

    if sockets == []:
        return

    while True:
        readables, writables, exceptionals = select.select(sockets, [], [])
        for oSocket in readables:
            ConnectionThread(oSocket, oOutput, options).start()

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-t', '--timeout', type=int, default=10, help='Timeout value for sockets in seconds (default 10s)')
    oParser.add_option('-r', '--readbuffer', type=int, default=10240, help='Size read buffer in bytes (default 10240)')
    oParser.add_option('-a', '--address', default='0.0.0.0', help='Address to listen on (default 0.0.0.0)')
    oParser.add_option('-P', '--ports', default='', help='Ports to listen on (overrides ports configured in the program)')
    oParser.add_option('-p', '--extraports', default='', help='Extra ports to listen on (default none)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 0:
        print('Error: no arguments expected')
        return

    TCPHoneypot(options)

if __name__ == '__main__':
    Main()
