#!/usr/bin/env python

__description__ = 'Template binary file argument'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2017/01/28'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2017/01/28: start

Todo:
"""

import optparse
import sys
import os
import textwrap
import magic

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

class MyMagic():
    def __init__(self):
        self.oMagic=magic.Magic(magic_file=r'C:\Program Files (x86)\GnuWin32\share\misc\magic')

        filename = os.path.join(os.path.dirname(sys.argv[0]), 'file-magic.def')
        if os.path.isfile(filename):
#        self.oMagicCustom=magic.Magic(magic_file=r'mymagic', keep_going=True)
            self.oMagicCustom = magic.Magic(magic_file=filename)
        else:
            print('Warning: custom magic file not found: %s' % filename)
            self.oMagicCustom = None


    def identify(self, data):
        filemagic = self.oMagic.from_buffer(data)
        if filemagic == 'data' and self.oMagicCustom != None:
            filemagic = self.oMagicCustom.from_buffer(data)
        return filemagic

def FileMagic(filename, options):
        if filename == '':
            fIn = sys.stdin
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            data = fIn.read()
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

        oMyMagic = MyMagic()
        if options.scan:
            for i in range(len(data)):
                filemagic = oMyMagic.identify(data[i:])
                if filemagic != 'data':
                    print('%08x: %s ' % (i, filemagic))
        else:
            print(oMyMagic.identify(data))

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-p', '--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('-s', '--scan', action='store_true', default=False, help='Scan')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        FileMagic('', options)
    elif len(args) == 1:
        FileMagic(args[0], options)
    else:
        oParser.print_help()

if __name__ == '__main__':
    Main()
