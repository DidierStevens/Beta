#!/usr/bin/env python

__description__ = 'Wrapper for uncompyle6'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2016/12/05'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/12/03: start
  2016/12/05: continue

Todo:
"""

import optparse
import sys
import os
import textwrap
import marshal
import dis
from io import StringIO

from uncompyle6.main import uncompyle

def PrintManual():
    manual = '''
Manual:

TBD
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

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

def ProcessPyc(data, options):
    pythoncode = marshal.loads(data[8:])
    
    if options.disassemble:
        dis.dis(pythoncode[-1])
    else:
        oStringIO = StringIO()
        uncompyle(options.versionpython, pythoncode[-1], oStringIO)
        print(oStringIO.getvalue())

def Processpy2exe(data, options):
    data = data[0x010:]
    offset = data.find(b"\x00")
    if offset == -1:
        return
    pythoncode = marshal.loads(data[offset + 1:])
    
    if options.disassemble:
        dis.dis(pythoncode[-1])
    else:
        oStringIO = StringIO()
        uncompyle(options.versionpython, pythoncode[-1], oStringIO)
        print(oStringIO.getvalue())

def ProcessFile(filename, options):
        if filename == '':
            data = sys.stdin.buffer.read()
        elif filename.lower().endswith('.zip'):
            oZipfile = zipfile.ZipFile(filename, 'r')
            oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(options.password))
            data = oZipContent.read()
            oZipContent.close()
            oZipfile.close()
        else:
            fIn = open(filename, 'rb')
            data = fIn.read()
            fIn.close()

        if data[:4] == C2BIP3('\x12\x34\x56\x78'):
            Processpy2exe(data, options)
        else:
            ProcessPyc(data, options)

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-p', '--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('-d', '--disassemble', action='store_true', default=False, help='Disassemble')
    oParser.add_option('-v', '--versionpython', type=float, default=3.4, help='The python version of the code (default 3.5)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        ProcessFile('', options)
    elif len(args) == 1:
        ProcessFile(args[0], options)
    else:
        oParser.print_help()

if __name__ == '__main__':
    Main()
