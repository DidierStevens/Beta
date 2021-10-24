#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Analyze Cobalt Strike HTTP beacon traffic'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2021/10/10'

"""

Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2021/04/17: start
  2021/04/18: continue
  2021/04/19: added option -r
  2021/04/20: added option -Y; continue
  2021/04/22: continue
  2021/04/23: continue
  2021/04/24: continue
  2021/10/10: continue

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
import hmac
import Crypto.Cipher.AES

CS_FIXED_IV = b'abcdefghijklmnop'

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
    32: 'LIST_PROCESSES',
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

class cCrypto(object):

    def __init__(self, rawkey='', hmacaeskeys=''):
        self.rawkey = rawkey
        self.hmacaeskeys = hmacaeskeys
        if self.rawkey != '':
            sha256digest = hashlib.sha256(binascii.a2b_hex(self.rawkey)).digest()
            self.hmackey = sha256digest[16:]
            self.aeskey = sha256digest[:16]
        elif self.hmacaeskeys != '':
            self.hmackey = binascii.a2b_hex(self.hmacaeskeys.split(':')[0])
            self.aeskey = binascii.a2b_hex(self.hmacaeskeys.split(':')[1])
        else:
            self.hmackey = None
            self.aeskey = None

    def Decrypt(self, data):
        if self.aeskey == None:
            return data
        encryptedData = data[:-16]
        hmacSignatureMessage = data[-16:]
        hmacsSgnatureCalculated = hmac.new(self.hmackey, encryptedData, hashlib.sha256).digest()[:16]
        if hmacSignatureMessage != hmacsSgnatureCalculated:
            raise Exception('HMAC signature invalid')
        cypher = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, CS_FIXED_IV)
        decryptedData = cypher.decrypt(encryptedData)
        return decryptedData

    def Encrypt(self, data):
        cypher = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, CS_FIXED_IV)
        encryptedData = cypher.encrypt(data)
        hmacsSgnatureCalculated = hmac.new(self.hmackey, encryptedData, hashlib.sha256).digest()[:16]
        return encryptedData + hmacsSgnatureCalculated

class cStruct(object):
    def __init__(self, data):
        self.data = data
        self.originaldata = data

    def Unpack(self, format):
        formatsize = struct.calcsize(format)
        if len(self.data) < formatsize:
            raise Exception('Not enough data')
        tounpack = self.data[:formatsize]
        self.data = self.data[formatsize:]
        result = struct.unpack(format, tounpack)
        if len(result) == 1:
            return result[0]
        else:
            return result

    def Truncate(self, length):
        self.data = self.data[:length]
        
    def GetBytes(self, length=None):
        if length == None:
            length = len(self.data)
        result = self.data[:length]
        self.data = self.data[length:]
        return result

    def GetString(self, format):
        stringLength = self.Unpack(format)
        return self.GetBytes(stringLength)

    def Length(self):
        return len(self.data)

def ProcessReplyPacketData(hexdata, oOutput, oCrypto, options):
    try:
        data = oCrypto.Decrypt(binascii.a2b_hex(hexdata))
    except Exception as e:
        if e.args != ('HMAC signature invalid',):
            raise
        oOutput.Line('HMAC signature invalid\n')
        return
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
                if argslen > 0:
                    if command in [40, 62]:
                        payload = data[:argslen]
                        oStruct = cStruct(payload)
                        oOutput.Line(' Unknown1: %d' % oStruct.Unpack('>I'))
                        oOutput.Line(' Unknown2: %d' % oStruct.Unpack('>I'))
                        oOutput.Line(' Pipename: %s' % oStruct.GetString('>I'))
                        oOutput.Line(' Command: %s' % oStruct.GetString('>I'))
                        oOutput.Line(' ' + repr(oStruct.GetBytes()))
                    else:
                        oOutput.Line(' ' + repr(data[:argslen])[:100])
                        payload = data[:argslen]
                        oOutput.Line(' MD5: ' + hashlib.md5(payload).hexdigest())
                        ExtractPayload(payload, options)
            data = data[argslen:]

    oOutput.Line('')

def ProcessPostPacketDataSub(data, oOutput, oCrypto, options):
    oStructData = cStruct(oCrypto.Decrypt(data))
    counter = oStructData.Unpack('>I')
    oOutput.Line('Counter: %d' % counter)
    oStructCallbackdata = cStruct(oStructData.GetString('>I'))
    callback = oStructCallbackdata.Unpack('>I')
    callbackdata = oStructCallbackdata.GetBytes()
    oOutput.Line('Callback: %d %s' % (callback, BEACON_OUTPUT.get(callback, 'UNKNOWN')))
    if callback in [0, 25]:
        oOutput.Line('-' * 100)
        oOutput.Line(callbackdata.decode())
        oOutput.Line('-' * 100)
    elif callback == 22:
        oOutput.Line(repr(callbackdata[:4]))
        oOutput.Line('-' * 100)
        oOutput.Line(callbackdata[4:].decode('latin'))
        oOutput.Line('-' * 100)
    elif callback in [17, 30, 32]:
        oOutput.Line(callbackdata.decode())
    elif callback in [3, 8]:
        oOutput.Line(' MD5: ' + hashlib.md5(callbackdata[4:]).hexdigest())
        ExtractPayload(callbackdata, options)
    else:
        oOutput.Line(repr(callbackdata))
    extradata = oStructData.GetBytes()[:-16] # drop hmac
    oOutput.Line('Extra packet data: %s' % repr(extradata))

    oOutput.Line('')

def ProcessPostPacketData(hexdata, oOutput, oCrypto, options):
    oStructData = cStruct(binascii.a2b_hex(hexdata))
    while oStructData.Length() > 0:
        ProcessPostPacketDataSub(oStructData.GetString('>I'), oOutput, oCrypto, options)

def AnalyzeCapture(filename, options):
    oOutput = InstantiateCOutput(options)

    if options.hmacaeskeys != '':
        oCrypto = cCrypto(hmacaeskeys=options.hmacaeskeys)
    else:
        oCrypto = cCrypto(rawkey=options.rawkey)

    capture = pyshark.FileCapture(filename, display_filter=options.displayfilter, use_json=True)
    for packet in capture:
        if not hasattr(packet, 'http'):
            continue
        if not hasattr(packet, 'data'):
            continue

        if hasattr(packet.http, 'response'):
            oOutput.Line('Packet number: %d' % packet.number)
            oOutput.Line('HTTP response')
            ProcessReplyPacketData(packet.data.data.replace(':', ''), oOutput, oCrypto, options)

        if hasattr(packet.http, 'request'):
            oOutput.Line('Packet number: %d' % packet.number)
            oOutput.Line('HTTP request')
            oOutput.Line(packet.http.full_uri)
            ProcessPostPacketData(packet.data.data.replace(':', ''), oOutput, oCrypto, options)

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
    oParser.add_option('-r', '--rawkey', type=str, default='', help="CS beacon's raw key")
    oParser.add_option('-k', '--hmacaeskeys', type=str, default='', help="HMAC and AES keys in hexadecimal separated by :")
    oParser.add_option('-Y', '--displayfilter', type=str, default='http', help="Tshark display filter (default http)")
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    ProcessArguments(args, options)

if __name__ == '__main__':
    Main()
