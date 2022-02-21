#!/usr/bin/env python

__description__ = 'SMTP honeypot'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2022/02/21'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2018/03/24: start
  2022/02/21: Python 3 fix

Todo:
"""

import optparse
import smtpd
import asyncore
import re
import time
import textwrap

def PrintManual():
    manual = r'''
Manual:

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

class cSMTPServer(smtpd.SMTPServer):

    def process_message(self, peer, mailfrom, rcpttos, data):
        global oOutput

        subject = ''
        oMatch = re.search('\nSubject: ([^\n]+)\n', data)
        if oMatch != None:
            subject = repr(oMatch.groups()[0])

        oOutput.LineTimestamped('Email: %s %s %s %s' % (repr(peer), repr(mailfrom), repr(rcpttos), subject))

        f = open('%s-%s.eml' % (FormatTime(), ''.join([c for c in subject.replace(' ', '_') if c.lower() in 'abcdefghijklmnopqrstuvwxyz0123456789_'])), 'wb')
        f.write(data.encode())
        f.close()

def SMTPHoneypot(options):
    global oOutput

    oOutput = cOutput('smtp-honeypot-%s.log' % FormatTime(), True)

    servers = []
    smtpd.__version__ = ''
    for port in ParsePorts(options.ports):
        servers.append(cSMTPServer((options.address, port), None))
        oOutput.LineTimestamped('STARTED listening %s %d' % (options.address, port))

    asyncore.loop()

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-a', '--address', default='0.0.0.0', help='Address to listen on (default 0.0.0.0)')
    oParser.add_option('-p', '--ports', default='25', help='The TCP ports to listen on (default 25)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 0:
        print('Error: no arguments expected')
        return

    SMTPHoneypot(options)

if __name__ == '__main__':
    Main()
