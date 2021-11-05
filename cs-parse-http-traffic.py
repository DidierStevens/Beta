#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Analyze Cobalt Strike HTTP beacon traffic'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2021/11/05'

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
  2021/10/07: updated missing modules logic
  2021/10/17: 0.0.2 added option -i; -r unknown and -k unknown
  2021/10/28: handle fake gzip
  2021/10/30: continue instructions processing
  2021/10/31: added request methods
  2021/11/01: refactoring instructions processing
  2021/11/05: refactoring instructions processing

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
import hmac
import base64
try:
    import pyshark
except ImportError:
    print('pyshark module required: pip install pyshark')
    exit(-1)
try:
    import Crypto.Cipher.AES
except ImportError:
    print('Crypto.Cipher.AES module required: pip install pycryptodome')
    exit(-1)

CS_FIXED_IV = b'abcdefghijklmnop'

def PrintManual():
    manual = '''
Manual:

This tool is to be defined.

# https://github.com/nccgroup/pybeacon

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

BEACON_COMMAND_SLEEP = 4
BEACON_COMMAND_DATA_JITTER = 6
BEACON_COMMAND_RUN = 78

BEACON_COMMANDS = {
    BEACON_COMMAND_SLEEP:  'SLEEP',
    BEACON_COMMAND_DATA_JITTER:  'DATA_JITTER',
    11: 'DOWNLOAD_START',
    32: 'LIST_PROCESSES',

    3: 'EXIT',
    5: 'CD',
    8: 'CHECKIN',
    11: 'DOWNLOAD',
    12: 'EXECUTE',
    13: 'Tasked beacon to spawn features to default process',
    27: 'GETUID',
    28: 'REVERT_TOKEN',
    33: 'KILL',
    39: 'PWD',
    41: 'JOBS',
    48: 'IP_CONFIG',
    53: 'LIST_FILES',
    54: 'MKDIR',
    55: 'DRIVES',
    56: 'RM',
    72: 'SETENV',
    73: 'CP',
    74: 'MV',
    77: 'GETPRIVS',
    BEACON_COMMAND_RUN: 'RUN',
    80: 'DLLLOAD',
    85: 'ARGUE',
    95: 'GETSYSTEM',
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
    30: 'OUTPUT',
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
        self.dReplacements = {}

    def Replace(self, line):
        for key, value in self.dReplacements.items():
            line = line.replace(key, value)
        return line

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
        line = self.Replace(line)
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
        if self.rawkey != '' and self.rawkey != 'unknown':
            sha256digest = hashlib.sha256(binascii.a2b_hex(self.rawkey)).digest()
            self.hmackey = sha256digest[16:]
            self.aeskey = sha256digest[:16]
        elif self.hmacaeskeys != '' and self.hmacaeskeys != 'unknown':
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

def BASE64URLDecode(data):
    paddingLength = 4 - len(data) % 4
    if paddingLength <= 2:
        data += b'=' * paddingLength
    return base64.b64decode(data, b'-_')

def StartsWithGetRemainder(strIn, strStart):
    if strIn.startswith(strStart):
        return True, strIn[len(strStart):]
    else:
        return False, None
    
def GetInstructions(instructions, instructionType):
    for result in instructions.split(';'):
        match, remainder = StartsWithGetRemainder(result, '7:%s,' % instructionType)
        if match:
            if instructionType == 'Output':
                return ','.join(remainder.split(',')[::-1])
            else:
                return remainder
    return ''

def ProcessInstructions(instructions, rawdata, instructionType):
    instructions = GetInstructions(instructions, instructionType)
    if instructions == '':
        instructions = []
    else:
        instructions = [instruction for instruction in instructions.split(',')]
    data = rawdata
    for instruction in instructions:
        instruction = instruction.split(':')
        opcode = int(instruction[0])
        operands = instruction[1:]
        if opcode == 1:
            data = data[:-int(operands[0])]
        elif opcode == 2:
            data = data[int(operands[0]):]
        elif opcode == 3:
            data = binascii.a2b_base64(data)
        elif opcode == 4:
            pass
        elif opcode == 7:
            pass
        elif opcode == 13:
            data = BASE64URLDecode(data)
        elif opcode == 15:
            xorkey = data[0:4]
            ciphertext = data[4:]
            data = []
            for iter, value in enumerate(ciphertext):
                data.append(value ^ xorkey[iter % 4])
            data = bytes(data)
    return data
            
def ProcessReplyPacketData(hexdata, oOutput, oCrypto, dCommandsSummary, options):
    rawdata = binascii.a2b_hex(hexdata)
    oOutput.Line('Length raw data: %s' % len(rawdata))
    rawdata = ProcessInstructions(options.transform, rawdata, 'Input')
    if rawdata == b'':
        oOutput.Line('No data')
        oOutput.Line('')
        return
    if options.rawkey == 'unknown' or options.hmacaeskeys == 'unknown':
        oOutput.Line(binascii.b2a_hex(rawdata).decode())
        oOutput.Line('')
        return
    try:
        data = oCrypto.Decrypt(rawdata)
    except Exception as e:
        if e.args != ('HMAC signature invalid',):
            raise
        oOutput.Line('HMAC signature invalid')
        return
    if data == b'':
        oOutput.Line('No data')
    elif data.startswith(b'MZ'):
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
            dCommandsSummary[command] = dCommandsSummary.get(command, 0) + 1
            oOutput.Line('Command: %d %s' % (command, BEACON_COMMANDS.get(command, 'UNKNOWN')))
            if command == BEACON_COMMAND_SLEEP:
                sleep, jitter, _ = Unpack('>II', data)
                oOutput.Line(' Sleep: %d' % sleep)
                oOutput.Line(' Jitter: %d' % jitter)
            elif command == BEACON_COMMAND_DATA_JITTER:
                oOutput.Line(' Length random data = %d' % argslen)
            elif command == BEACON_COMMAND_RUN:
                payload = data[:argslen]
                oStruct = cStruct(payload)
                oOutput.Line(' Command: %s' % oStruct.GetString('>I'))
                oOutput.Line(' Arguments: %s' % oStruct.GetString('>I'))
                oOutput.Line(' Integer: %d' % oStruct.Unpack('>H'))
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

def ProcessPostPacketDataSub(data, oOutput, oCrypto, dCallbacksSummary, options):
    oStructData = cStruct(oCrypto.Decrypt(data))
    counter = oStructData.Unpack('>I')
    oOutput.Line('Counter: %d' % counter)
    oStructCallbackdata = cStruct(oStructData.GetString('>I'))
    callback = oStructCallbackdata.Unpack('>I')
    callbackdata = oStructCallbackdata.GetBytes()
    oStructCallbackdataToParse = cStruct(callbackdata)
    oOutput.Line('Callback: %d %s' % (callback, BEACON_OUTPUT.get(callback, 'UNKNOWN')))
    dCallbacksSummary[callback] = dCallbacksSummary.get(callback, 0) + 1
    if callback in [0, 25]:
        oOutput.Line('-' * 100)
        oOutput.Line(callbackdata.decode())
        oOutput.Line('-' * 100)
    elif callback == 22:
        oOutput.Line(repr(callbackdata[:4]))
        oOutput.Line('-' * 100)
        oOutput.Line(callbackdata[4:].decode('latin'))
        oOutput.Line('-' * 100)
    elif callback == 2:
        parameter1, length = oStructCallbackdataToParse.Unpack('>II')
        filenameDownload = oStructCallbackdataToParse.GetBytes()
        oOutput.Line(' parameter1: %d' % parameter1)
        oOutput.Line(' length: %d' % length)
        oOutput.Line(' filenameDownload: %s' % filenameDownload.decode())
    elif callback in [17, 30, 32]:
        oOutput.Line(callbackdata.decode())
    elif callback in [3, 8]:
        oOutput.Line(' Length: %d' % len(callbackdata[4:]))
        oOutput.Line(' MD5: ' + hashlib.md5(callbackdata[4:]).hexdigest())
        ExtractPayload(callbackdata[4:], options)
    else:
        oOutput.Line(repr(callbackdata))
    extradata = oStructData.GetBytes()[:-16] # drop hmac
    if len(extradata) > 0:
        oOutput.Line('Extra packet data: %s' % repr(extradata))

    oOutput.Line('')

def ProcessPostPacketData(hexdata, oOutput, oCrypto, dCallbacksSummary, options):
    rawdata = binascii.a2b_hex(hexdata)
    oOutput.Line('Length raw data: %s' % len(rawdata))
    rawdata = ProcessInstructions(options.transform, rawdata, 'Output')
    if rawdata == b'':
        oOutput.Line('No data')
        oOutput.Line('')
        return
    if options.rawkey == 'unknown' or options.hmacaeskeys == 'unknown':
        oOutput.Line(binascii.b2a_hex(rawdata).decode())
        oOutput.Line('')
        return
    oStructData = cStruct(rawdata)
    while oStructData.Length() > 0:
        ProcessPostPacketDataSub(oStructData.GetString('>I'), oOutput, oCrypto, dCallbacksSummary, options)

def AnalyzeCapture(filename, options):
    oOutput = InstantiateCOutput(options)

    if options.hmacaeskeys != '':
        oCrypto = cCrypto(hmacaeskeys=options.hmacaeskeys)
    else:
        oCrypto = cCrypto(rawkey=options.rawkey)

    dMethods = {}
    dCommandsSummary = {}
    dCallbacksSummary = {}
    capture = pyshark.FileCapture(filename, display_filter=options.displayfilter, use_json=True, include_raw=True)
    for packet in capture:
        if not hasattr(packet, 'http'):
            continue

        if hasattr(packet.http, 'request') and packet.http.has_field('1\\r\\n'): # this is a bug in PyShark, should be fieldname request
            dMethods[packet.number] = packet.http.get_field('1\\r\\n').method

        data_raw = None
        if hasattr(packet.http, 'file_data_raw'):
            data_raw = packet.http.file_data_raw
        elif hasattr(packet.http, 'content-encoded_entity_body_(gzip)'):
            data_raw = getattr(packet.http, 'content-encoded_entity_body_(gzip)').data.data_raw
        else:
            continue

        if hasattr(packet.http, 'response'):
            oOutput.Line('Packet number: %d' % packet.number)
            if hasattr(packet.http, 'request_in') and len(packet.http.request_in.fields) > 0:
                requestPacket = packet.http.request_in.fields[0].int_value
                oOutput.Line('HTTP response (for request %d %s)' % (requestPacket, dMethods.get(requestPacket, '')))
            else:
                oOutput.Line('HTTP response')
            ProcessReplyPacketData(data_raw[0], oOutput, oCrypto, dCommandsSummary, options)

        if hasattr(packet.http, 'request'):
            oOutput.Line('Packet number: %d' % packet.number)
            oOutput.Line('HTTP request %s' % dMethods.get(packet.number, ''))
            oOutput.Line(packet.http.full_uri)
            ProcessPostPacketData(data_raw[0], oOutput, oCrypto, dCallbacksSummary, options)

    capture.close()

    if len(dCommandsSummary) > 0:
        oOutput.Line('\nCommands summary:')
        for command, counter in sorted(dCommandsSummary.items()):
            oOutput.Line(' %d %s: %d' % (command, BEACON_COMMANDS.get(command, 'UNKNOWN'), counter))

    if len(dCallbacksSummary) > 0:
        oOutput.Line('\nCallbacks summary:')
        for callback, counter in sorted(dCallbacksSummary.items()):
            oOutput.Line(' %d %s: %d' % (callback, BEACON_OUTPUT.get(callback, 'UNKNOWN'), counter))

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
    oParser.add_option('-t', '--transform', type=str, default='', help='Transformation instructions')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    ProcessArguments(args, options)

if __name__ == '__main__':
    Main()
