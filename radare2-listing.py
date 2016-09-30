#!/usr/bin/env python

__description__ = "Program to add information to radare2 listing"
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2016/09/28'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/09/15: start
  2016/09/21: continue
  2016/09/28: all text on one line

Todo:
"""

import optparse
import glob
import collections
import re
import sys
import textwrap
import binascii

def PrintManual():
    manual = '''
Manual:

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

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

class cOutput():
    def __init__(self, filename=None):
        self.filename = filename
        if self.filename and self.filename != '':
            self.f = open(self.filename, 'w')
        else:
            self.f = None

    def Line(self, line):
        if self.f:
            self.f.write(line + '\n')
        else:
            print(line)

    def Close(self):
        if self.f:
            self.f.close()
            self.f = None

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

class cOutputResult():
    def __init__(self, options):
        if options.output:
            self.oOutput = cOutput(options.output)
        else:
            self.oOutput = cOutput()
        self.options = options

    def Line(self, line):
        self.oOutput.Line(line)

    def Close(self):
        self.oOutput.Close()

def ProcessFile(fIn, fullread):
    if fullread:
        yield fIn.read()
    else:
        for line in fIn:
            yield line.strip('\n')

def Radare2ListingSingle(filenames, oOutput, options):
    oRE = re.compile('0x[0-9a-fA-F]{4,}')
    for filename in filenames:
        if filename == '':
            fIn = sys.stdin
        else:
            fIn = open(filename, 'r')
        comment = ''
        lines = []
        for line in [line.strip('\r\n\a') for line in ProcessFile(fIn, False)] + ['']:
            if line[12:14] == '0x':
                code = line[42:]
                position = code.find(';')
                if position != -1:
                    code = code[:position]
                oMatch = oRE.search(code)
                if oMatch != None and len(oMatch.group(0)[2:]) % 2 == 0:
#                    comment = " ; '%s'" % ''.join([IFF(b < chr(32) or b > chr(127), '.', b) for b in binascii.a2b_hex(oMatch.group(0)[2:])[::-1]])
                    comment += ''.join([IFF(b < chr(32) or b > chr(127), '.', b) for b in binascii.a2b_hex(oMatch.group(0)[2:])[::-1]])
                    lines.append(line)
                else:
                    if comment == '':
                        oOutput.Line(line)
                    else:
                        oOutput.Line(lines[0] + " ; '%s'" % comment)
                        for line1 in lines[1:]:
                            oOutput.Line(line1)
                        comment = ''
                        lines = []
            else:
                oOutput.Line(line)
        if fIn != sys.stdin:
            fIn.close()

def Radare2Listing(filenames, options):
    oOutput = cOutputResult(options)
    Radare2ListingSingle(filenames, oOutput, options)
    oOutput.Close()

def Main():
    global dLibrary

    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [expression [[@]file ...]]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        Radare2Listing([''], options)
    else:
        Radare2Listing(ExpandFilenameArguments(args), options)

if __name__ == '__main__':
    Main()
