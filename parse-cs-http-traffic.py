#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Analyze Cobalt Strike HTTP beacon unencrypted (trial)'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2021/04/17'

"""

Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2021/04/17: start
  2021/04/18: continue

Todo:
"""

import optparse
import glob
import collections
import time
import sys
import textwrap
import os
import binascii
import struct
import hashlib
import pyshark

def PrintManual():
    manual = '''
Manual:

This tool is to be defined.

# https://github.com/nccgroup/pybeacon

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

BEACON_COMMANDS = {
    4:  'SLEEP',
    11: 'DOWNLOAD_START',
    32: 'LIST_PROCESSES'
    }

BEACON_OUTPUT = {
    1: 'OUTPUT_KEYSTROKES',
    2: 'DOWNLOAD_START',
    3: 'OUTPUT_SCREENSHOT',
    4: 'SOCKS_DIE',
    5: 'SOCKS_WRITE',
    6: 'SOCKS_RESUME',
    7: 'SOCKS_PORTFWD',
    8: 'DOWNLOAD_WRITE',
    9: 'DOWNLOAD_COMPLETE',
    10: 'BEACON_LINK',
    11: 'DEAD_PIPE',
    12: 'BEACON_CHECKIN', # maybe?
    13: 'BEACON_ERROR',
    14: 'PIPES_REGISTER', # unsure?
    15: 'BEACON_IMPERSONATED',
    16: 'BEACON_GETUID',
    17: 'BEACON_OUTPUT_PS',
    18: 'ERROR_CLOCK_SKEW',
    19: 'BEACON_GETCWD',
    20: 'BEACON_OUTPUT_JOBS',
    21: 'BEACON_OUTPUT_HASHES',
    22: 'TODO', # find out
    23: 'SOCKS_ACCEPT',
    24: 'BEACON_OUTPUT_NET',
    25: 'BEACON_OUTPUT_PORTSCAN',
    26: 'BEACON_EXIT',
    }

class cOutput():
    def __init__(self, filenameOption=None):
        self.starttime = time.time()
        self.filenameOption = filenameOption
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.fOut = None
        self.rootFilenames = {}
        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles and self.filename != '':
                    self.fOut = open(self.filename, 'w')
            elif self.filenameOption != '':
                self.fOut = open(self.filenameOption, 'w')

    def ParseHash(self, option):
        if option.startswith('#'):
            position = self.filenameOption.find('#', 1)
            if position > 1:
                switches = self.filenameOption[1:position]
                self.filename = self.filenameOption[position + 1:]
                for switch in switches:
                    if switch == 's':
                        self.separateFiles = True
                    elif switch == 'p':
                        self.progress = True
                    elif switch == 'c':
                        self.console = True
                    elif switch == 'l':
                        pass
                    elif switch == 'g':
                        if self.filename != '':
                            extra = self.filename + '-'
                        else:
                            extra = ''
                        self.filename = '%s-%s%s.txt' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], extra, self.FormatTime())
                    else:
                        return False
                return True
        return False

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def RootUnique(self, root):
        if not root in self.rootFilenames:
            self.rootFilenames[root] = None
            return root
        iter = 1
        while True:
            newroot = '%s_%04d' % (root, iter)
            if not newroot in self.rootFilenames:
                self.rootFilenames[newroot] = None
                return newroot
            iter += 1

    def Line(self, line, eol='\n'):
        if self.fOut == None or self.console:
            try:
                print(line, end=eol)
            except UnicodeEncodeError:
                encoding = sys.stdout.encoding
                print(line.encode(encoding, errors='backslashreplace').decode(encoding), end=eol)
#            sys.stdout.flush()
        if self.fOut != None:
            self.fOut.write(line + '\n')
            self.fOut.flush()

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (self.FormatTime(), line))

    def Filename(self, filename, index, total):
        self.separateFilename = filename
        if self.progress:
            if index == 0:
                eta = ''
            else:
                seconds = int(float((time.time() - self.starttime) / float(index)) * float(total - index))
                eta = 'estimation %d seconds left, finished %s ' % (seconds, self.FormatTime(time.time() + seconds))
            PrintError('%d/%d %s%s' % (index + 1, total, eta, self.separateFilename))
        if self.separateFiles and self.filename != '':
            oFilenameVariables = cVariables()
            oFilenameVariables.SetVariable('f', self.separateFilename)
            basename = os.path.basename(self.separateFilename)
            oFilenameVariables.SetVariable('b', basename)
            oFilenameVariables.SetVariable('d', os.path.dirname(self.separateFilename))
            root, extension = os.path.splitext(basename)
            oFilenameVariables.SetVariable('r', root)
            oFilenameVariables.SetVariable('ru', self.RootUnique(root))
            oFilenameVariables.SetVariable('e', extension)

            self.Close()
            self.fOut = open(oFilenameVariables.Instantiate(self.filename), 'w')

    def Close(self):
        if self.fOut != None:
            self.fOut.close()
            self.fOut = None

def InstantiateCOutput(options):
    filenameOption = None
    if options.output != '':
        filenameOption = options.output
    return cOutput(filenameOption)

def Unpack(format, data):
    size = struct.calcsize(format)
    result = list(struct.unpack(format, data[:size]))
    result.append(data[size:])
    return result

def FormatTime(epoch=None):
    if epoch == None:
        epoch = time.time()
    return '%04d%02d%02d-%02d%02d%02d' % time.gmtime(epoch)[0:6]

def ExtractPayload(data, options):
    if options.extract:
        with open('payload-%s.vir' % hashlib.md5(data).hexdigest(), 'wb') as fWrite:
            fWrite.write(data)

def ProcessReplyPacketData(hexdata, oOutput, options):
    data = binascii.a2b_hex(hexdata)
    if data.startswith(b'MZ'):
        oOutput.Line('MZ payload detected')
        oOutput.Line(' MD5: ' + hashlib.md5(data).hexdigest())
        ExtractPayload(data, options)
    else:
        timestamp, datasize, data = Unpack('>II', data)
        oOutput.Line('Timestamp: %d %s' % (timestamp, FormatTime(timestamp)))
        oOutput.Line('Data size: %d' % datasize)
        data = data[:datasize]
        while len(data) > 0:
            command, argslen, data =  Unpack('>II', data)
            oOutput.Line('Command: %d %s' % (command, BEACON_COMMANDS.get(command, 'UNKNOWN')))
            if command == 4: #sleep
                sleep, jitter, _ = Unpack('>II', data)
                oOutput.Line(' Sleep: %d' % sleep)
                oOutput.Line(' Jitter: %d' % jitter)
            else:
                oOutput.Line(' Arguments length: %d' % argslen)
                oOutput.Line(' ' + repr(data[:argslen])[:100])
                payload = data[:argslen]
                oOutput.Line(' MD5: ' + hashlib.md5(payload).hexdigest())
                ExtractPayload(payload, options)
            data = data[argslen:]

    oOutput.Line('')

def ProcessPostPacketData(hexdata, oOutput, options):
    data = binascii.a2b_hex(hexdata)
    datasize, data = Unpack('>I', data)
    data = data[:datasize]
    counter, data = Unpack('>I', data)
    oOutput.Line('Counter: %d' % counter)
    size, data = Unpack('>I', data)
    callbackdata = data[:size]
    callback, callbackdata = Unpack('>I', callbackdata)
    oOutput.Line('Callback: %d %s' % (callback, BEACON_OUTPUT.get(callback, 'UNKNOWN')))
    if callback in [0, 25]:
        oOutput.Line('-' * 100)
        oOutput.Line(callbackdata.decode())
        oOutput.Line('-' * 100)
    elif callback == 22:
        oOutput.Line(repr(callbackdata[:4]))
        oOutput.Line('-' * 100)
        oOutput.Line(callbackdata[4:].decode())
        oOutput.Line('-' * 100)
    else:
        oOutput.Line(repr(callbackdata))
    data = data[size:]
    data = data[:-16] # drop hmac
    oOutput.Line('Extra packet data: %s' % repr(data))

    oOutput.Line('')

def AnalyzeCapture(filename, options):
    oOutput = InstantiateCOutput(options)

#    capture = pyshark.FileCapture('2019-07-25-Hancitor-style-Amadey-with-Pony-and-Cobalt-Strike.pcap', display_filter='ip.addr == 31.44.184.33', use_json=True)
    capture = pyshark.FileCapture(filename, display_filter='http', use_json=True)
    for packet in capture:
        if not hasattr(packet, 'http'):
            continue
        if not hasattr(packet, 'data'):
            continue

        if hasattr(packet.http, 'response'):
            oOutput.Line('Packet number: %d' % packet.number)
            oOutput.Line('HTTP response')
            ProcessReplyPacketData(packet.data.data.replace(':', ''), oOutput, options)

        if hasattr(packet.http, 'request'):
            oOutput.Line('Packet number: %d' % packet.number)
            oOutput.Line('HTTP request')
            oOutput.Line(packet.http.full_uri)
            ProcessPostPacketData(packet.data.data.replace(':', ''), oOutput, options)

    capture.close()

def ProcessArguments(filenames, options):
    for filename in filenames:
        AnalyzeCapture(filename, options)

def Main():
    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [[@]file ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file (# supported)')
    oParser.add_option('-e', '--extract', action='store_true', default=False, help='Extract payloads to disk')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    ProcessArguments(args, options)

if __name__ == '__main__':
    Main()
