#!/usr/bin/env python

__description__ = 'Tool to decode and search'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2016/09/27'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/09/20: start
  2016/09/21: continue
  2016/09/26: continue
  2016/09/27: continue

Todo:

"""

import optparse
import sys
import os
import zipfile
import textwrap
import re
import binascii
import cStringIO
import string
import math
import hashlib

dumplinelength = 16
MALWARE_PASSWORD = 'infected'
REGEX_STANDARD = '[\x09\x20-\x7E]'

def PrintManual():
    manual = '''
Manual:

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

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

def File2String(filename):
    try:
        f = open(filename, 'rb')
    except:
        return None
    try:
        return f.read()
    except:
        return None
    finally:
        f.close()

class cDumpStream():
    def __init__(self):
        self.text = ''

    def Addline(self, line):
        if line != '':
            self.text += line + '\n'

    def Content(self):
        return self.text

def HexDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0 and hexDump != '':
            oDumpStream.Addline(hexDump)
            hexDump = ''
        hexDump += IFF(hexDump == '', '', ' ') + '%02X' % ord(b)
    oDumpStream.Addline(hexDump)
    return oDumpStream.Content()

def CombineHexAscii(hexDump, asciiDump):
    if hexDump == '':
        return ''
    return hexDump + '  ' + (' ' * (3 * (dumplinelength - len(asciiDump)))) + asciiDump

def HexAsciiDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    asciiDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0:
            if hexDump != '':
                oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
            hexDump = '%08X:' % i
            asciiDump = ''
        hexDump+= ' %02X' % ord(b)
        asciiDump += IFF(ord(b) >= 32, b, '.')
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        try:
            sys.stdout.flush()
        except IOError:
            return
        data = data[10000:]

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

CUTTERM_NOTHING = 0
CUTTERM_POSITION = 1
CUTTERM_FIND = 2
CUTTERM_LENGTH = 3

def Replace(string, dReplacements):
    if string in dReplacements:
        return dReplacements[string]
    else:
        return string

def ParseCutTerm(argument):
    if argument == '':
        return CUTTERM_NOTHING, None, ''
    oMatch = re.match(r'\-?0x([0-9a-f]+)', argument, re.I)
    if oMatch == None:
        oMatch = re.match(r'\-?(\d+)', argument)
    else:
        value = int(oMatch.group(1), 16)
        if argument.startswith('-'):
            value = -value
        return CUTTERM_POSITION, value, argument[len(oMatch.group(0)):]
    if oMatch == None:
        oMatch = re.match(r'\[([0-9a-f]+)\](\d+)?([+-]\d+)?', argument, re.I)
    else:
        value = int(oMatch.group(1))
        if argument.startswith('-'):
            value = -value
        return CUTTERM_POSITION, value, argument[len(oMatch.group(0)):]
    if oMatch == None:
        oMatch = re.match(r"\[\'(.+?)\'\](\d+)?([+-]\d+)?", argument)
    else:
        if len(oMatch.group(1)) % 2 == 1:
            raise Exception("Uneven length hexadecimal string")
        else:
            return CUTTERM_FIND, (binascii.a2b_hex(oMatch.group(1)), int(Replace(oMatch.group(2), {None: '1'})), int(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]
    if oMatch == None:
        return None, None, argument
    else:
        return CUTTERM_FIND, (oMatch.group(1), int(Replace(oMatch.group(2), {None: '1'})), int(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]

def ParseCutArgument(argument):
    type, value, remainder = ParseCutTerm(argument.strip())
    if type == CUTTERM_NOTHING:
        return CUTTERM_NOTHING, None, CUTTERM_NOTHING, None
    elif type == None:
        if remainder.startswith(':'):
            typeLeft = CUTTERM_NOTHING
            valueLeft = None
            remainder = remainder[1:]
        else:
            return None, None, None, None
    else:
        typeLeft = type
        valueLeft = value
        if typeLeft == CUTTERM_POSITION and valueLeft < 0:
            return None, None, None, None
        if typeLeft == CUTTERM_FIND and valueLeft[1] == 0:
            return None, None, None, None
        if remainder.startswith(':'):
            remainder = remainder[1:]
        else:
            return None, None, None, None
    type, value, remainder = ParseCutTerm(remainder)
    if type == CUTTERM_POSITION and remainder == 'l':
        return typeLeft, valueLeft, CUTTERM_LENGTH, value
    elif type == None or remainder != '':
        return None, None, None, None
    elif type == CUTTERM_FIND and value[1] == 0:
        return None, None, None, None
    else:
        return typeLeft, valueLeft, type, value

def Find(data, value, nth):
    position = -1
    while nth > 0:
        position = data.find(value, position + 1)
        if position == -1:
            return -1
        nth -= 1
    return position

def CutData(stream, cutArgument):
    if cutArgument == '':
        return stream

    typeLeft, valueLeft, typeRight, valueRight = ParseCutArgument(cutArgument)

    if typeLeft == None:
        return stream

    if typeLeft == CUTTERM_NOTHING:
        positionBegin = 0
    elif typeLeft == CUTTERM_POSITION:
        positionBegin = valueLeft
    elif typeLeft == CUTTERM_FIND:
        positionBegin = Find(stream, valueLeft[0], valueLeft[1])
        if positionBegin == -1:
            return ''
        positionBegin += valueLeft[2]
    else:
        raise Exception("Unknown value typeLeft")

    if typeRight == CUTTERM_NOTHING:
        positionEnd = len(stream)
    elif typeRight == CUTTERM_POSITION and valueRight < 0:
        positionEnd = len(stream) + valueRight
    elif typeRight == CUTTERM_POSITION:
        positionEnd = valueRight + 1
    elif typeRight == CUTTERM_LENGTH:
        positionEnd = positionBegin + valueRight
    elif typeRight == CUTTERM_FIND:
        positionEnd = Find(stream, valueRight[0], valueRight[1])
        if positionEnd == -1:
            return ''
        else:
            positionEnd += len(valueRight[0])
        positionEnd += valueRight[2]
    else:
        raise Exception("Unknown value typeRight")

    return stream[positionBegin:positionEnd]

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        try:
            sys.stdout.flush()
        except IOError:
            return
        data = data[10000:]

def Magic(data):
    magicPrintable = ''
    magicHex = ''
    for iter in range(4):
        if len(data) >= iter + 1:
            if ord(data[iter]) >= 0x20 and ord(data[iter]) < 0x7F:
                magicPrintable += data[iter]
            else:
                magicPrintable += '.'
            magicHex += '%02x' % ord(data[iter])
    return magicPrintable, magicHex

def CalculateByteStatistics(dPrevalence):
    sumValues = sum(dPrevalence.values())
    countNullByte = dPrevalence[0]
    countControlBytes = 0
    countWhitespaceBytes = 0
    for iter in range(1, 0x21):
        if chr(iter) in string.whitespace:
            countWhitespaceBytes += dPrevalence[iter]
        else:
            countControlBytes += dPrevalence[iter]
    countControlBytes += dPrevalence[0x7F]
    countPrintableBytes = 0
    for iter in range(0x21, 0x7F):
        countPrintableBytes += dPrevalence[iter]
    countHighBytes = 0
    for iter in range(0x80, 0x100):
        countHighBytes += dPrevalence[iter]
    entropy = 0.0
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            prevalence = float(dPrevalence[iter]) / float(sumValues)
            entropy += - prevalence * math.log(prevalence, 2)
    return sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes

def CalculateFileMetaData(data):
    dPrevalence = {}
    for iter in range(256):
        dPrevalence[iter] = 0
    for char in data:
        dPrevalence[ord(char)] += 1

    fileSize, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    magicPrintable, magicHex = Magic(data[0:4])
    return hashlib.md5(data).hexdigest(), magicPrintable, magicHex, fileSize, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes

def ExtractStringsASCII(data):
    regex = REGEX_STANDARD + '{%d,}'
    return re.findall(regex % 4, data)

def ExtractStringsUNICODE(data):
    regex = '((' + REGEX_STANDARD + '\x00){%d,})'
    return [foundunicodestring.replace('\x00', '') for foundunicodestring, dummy in re.findall(regex % 4, data)]

def ExtractStrings(data):
    return ExtractStringsASCII(data) + ExtractStringsUNICODE(data)


def GenerateValues(variables, values, results):
    if variables != []:
        for i in range(int(variables[0][1][0]), int(variables[0][1][1]) + 1):
            GenerateValues(variables[1:], values + [[variables[0][0], str(i)]], results)
    else:
        results.append(values)

class cExpression():
    def __init__(self, expression, decoder, terms, action):
        self.expression = expression
        self.decoder= decoder
        self.terms = terms
        self.action = action

def ParseExpressionsFile(exprfilename):
    expressions = []
    expression = None
    decoder = None
    strings = []
    action = None
    for line in File2Strings(exprfilename):
        if line.startswith('#') or line.strip() == '':
            continue
        if line.startswith('expression '):
            if expression != None and strings != []:
                expressions.append(cExpression(expression, decoder, strings, action))
                expression = None
                strings = []
            if expression != None:
                print('Parsing error: string expected')
                return []
            else:
                expression = line[11:]
                strings = []
        elif line.startswith('string '):
            if expression == None:
                print('Parsing error: no expression')
                return []
            else:
                strings.append(line[7:])
        elif line.startswith('decoder '):
            if expression == None:
                print('Parsing error: no expression')
                return []
            else:
                decoder = line[8:]
        elif line.startswith('action '):
            if expression == None:
                print('Parsing error: no expression')
                return []
            else:
                action = line[7:]
        else:
            print('Parsing error: unknown line: ' % line)
            return []
    if expression != None and strings != []:
        expressions.append(cExpression(expression, decoder, strings, action))
    return expressions

def DecodeData(data, decoder):
    if decoder == None:
        return [data]
    elif decoder == 'base64':
        result = []
        for base64string in re.findall('[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/]+={0,2}', data):
            if len(base64string) % 4 == 0:
                try:
                    base64data = binascii.a2b_base64(base64string)
                    result.append(base64data)
                except:
                    pass
        return result
    else:
        print('Unknown decoder: ' + decoder)
        return []

def DecodeSearchSub(exprfilename, data, options):
    for oExpression in ParseExpressionsFile(exprfilename):
        dVariables = {}
        standardExpr = oExpression.expression
        for oMatch in re.finditer('%i(\d):([^%]+)%', oExpression.expression):
            if not oMatch.groups()[0] in dVariables:
                variable = '%i' + oMatch.groups()[0] + '%'
                standardExpr = standardExpr.replace(oMatch.group(0), variable)
                dVariables[oMatch.groups()[0]] = [variable, oMatch.groups()[1].split('-')]
        results = []
        GenerateValues([dVariables[key] for key in sorted(dVariables.keys())], [], results)
        for combination in results:
            expression = standardExpr
            for variable in combination:
                expression = expression.replace(variable[0], variable[1])
            if options.verbose:
                print(expression)
            for translateddata in DecodeData(eval("''.join([chr(" + expression + ") for byte in map(ord, data)])"), oExpression.decoder):
                for term in oExpression.terms:
                    position = translateddata.find(term)
                    if position != -1:
                        if options.asciidump:
                            StdoutWriteChunked(HexAsciiDump(translateddata))
                        elif  options.hexdump:
                            StdoutWriteChunked(HexDump(translateddata))
                        elif options.dump:
                            IfWIN32SetBinary(sys.stdout)
                            StdoutWriteChunked(translateddata)
                        else:
                            print('Found:')
                            print(' Search term: %s' % term)
                            print(' Position:    0x%08x (%d)' % (position, position))
                            print(' Expression:  %s' % expression)
                            if oExpression.decoder != None:
                                print(' Decoder:     %s' % oExpression.decoder)
                            filehash, magicPrintable, magicHex, fileSize, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateFileMetaData(translateddata)
                            print(' %s: %s' % ('MD5', filehash))
                            print(' %s: %d' % ('Size', fileSize))
                            print(' %s: %f' % ('Entropy', entropy))
                            print(' %s: %s' % ('Magic HEX', magicHex))
                            print(' %s: %s' % ('Magic ASCII', magicPrintable))
                            print(' %s: %s' % ('Null bytes', countNullByte))
                            print(' %s: %s' % ('Control bytes', countControlBytes))
                            print(' %s: %s' % ('Whitespace bytes', countWhitespaceBytes))
                            print(' %s: %s' % ('Printable bytes', countPrintableBytes))
                            print(' %s: %s' % ('High bytes', countHighBytes))
                            if oExpression.action == 'strings':
                                print('Strings:')
                                for extractedstring in ExtractStrings(translateddata):
                                    print(extractedstring)
                        return

def DecodeSearch(exprfilename, filename, options):
    if filename == '':
        IfWIN32SetBinary(sys.stdin)
        oStringIO = cStringIO.StringIO(sys.stdin.read())
    elif filename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(filename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        oStringIO = cStringIO.StringIO(oZipContent.read())
        oZipContent.close()
        oZipfile.close()
    else:
        oStringIO = cStringIO.StringIO(open(filename, 'rb').read())

    DecodeSearchSub(exprfilename, CutData(oStringIO.read(), options.cut), options)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] expr-file [file|zip]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-c', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='Verbose output')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if ParseCutArgument(options.cut)[0] == None:
        print('Error: the expression of the cut option (-c) is invalid: %s' % options.cut)
        return

    if len(args) > 2 or len(args) == 0:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
    elif len(args) == 1:
        DecodeSearch(args[0], '', options)
    else:
        DecodeSearch(args[0], args[1], options)

if __name__ == '__main__':
    Main()
