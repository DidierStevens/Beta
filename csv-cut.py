#!/usr/bin/env python

__description__ = 'Tool to select columns'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/08/13'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/02/14: start
  2014/08/03: added KeyboardInterrupt, stdin
  2014/08/04: added option unquoted
  2014/08/13: changed skipinitialspace, fixed header printing bug
  2015/08/13: Columns now uses separator specified by separator option; added support for \t separator

Todo:
"""

import csv
import optparse
import os
import gzip
import glob
import signal
import collections
import sys

QUOTE = '"'

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

def ToString(value):
    if type(value) == type(''):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if separator in value:
        return quote + value + quote
    else:
        return value

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

def Print(line, f):
    if f == None:
        print(line)
    else:
        f.write(line +'\n')

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

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

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

def PrintDictionary(dCount, dSelections, sortDescending, sortKeys, totals, nocounters, separator, output, uniques, minmax):
    if uniques:
        listCount = [(key, len(value)) for key, value in dCount.items()]
    elif minmax:
        listCount = [(key, [len(value), min(value), max(value)]) for key, value in dCount.items()]
    else:
        listCount = [(key, value) for key, value in dCount.items()]
    if sortKeys:
        index = 0
    else:
        index = 1
    listCount.sort(lambda x, y:cmp(x[index], y[index]), reverse=sortDescending)
    sumValues = 0
    if output:
        fOut = open(output, 'w')
    else:
        fOut = None
    for key, value in listCount:
        if nocounters:
            row = dSelections[key]
        else:
            if minmax:
                row = dSelections[key] + value
            else:
                row = dSelections[key] + [value]
        Print(MakeCSVLine(row, separator, QUOTE), fOut)
        if not minmax:
            sumValues += value
    if totals:
        Print(MakeCSVLine(['uniques', len(dCount.keys())], separator, QUOTE), fOut)
        Print(MakeCSVLine(['total', sumValues], separator, QUOTE), fOut)
    if output:
        fOut.close()

def ConvertHeaderToIndex(header, separator, columns):
    try:
        result = []
        for column in columns.split(separator):
            result.append(header.index(column))
        return result
    except:
        return None

def CSVCut(columns, files, options):
    FixPipe()
    columnsToProcess = [column for column in columns.split(options.separator)]
    columnsIndices = None
    if not options.header:
        columnsIndices = [int(columnIndex) for columnIndex in columnsToProcess]
    if options.output:
        fOut = open(options.output, 'w')
    else:
        fOut = None
    headerPrinted = False
    for file in files:
        if file == '':
            fIn = sys.stdin
        elif os.path.splitext(file)[1].lower() == '.gz':
            fIn = gzip.GzipFile(file, 'rb')
        else:
            fIn = open(file, 'rb')
        reader = csv.reader(fIn, delimiter=options.separator, skipinitialspace=False, quoting=IFF(options.unquoted, csv.QUOTE_NONE, csv.QUOTE_MINIMAL))
        firstRow = True
        for row in reader:
            try:
                if options.header and firstRow:
                    firstRow = False
                    columnsIndices = ConvertHeaderToIndex(row, options.separator, columns)
                    if columnsIndices == None:
                        print('Columns %s not found in file %s' % (columns, file))
                        return
                    if not headerPrinted:
                        Print(MakeCSVLine([row[columnsIndex] for columnsIndex in columnsIndices], options.separator, QUOTE), fOut)
                        headerPrinted = True
                    continue
                Print(MakeCSVLine([row[columnsIndex] for columnsIndex in columnsIndices], options.separator, QUOTE), fOut)
            except KeyboardInterrupt:
                raise    
            except:
                pass

        if fIn != sys.stdin:
            fIn.close()
    if fOut:
        fOut.close()

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] columns files\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-s', '--separator', default=';', help='Separator character (default ;)')
    oParser.add_option('-o', '--output', help='Output to file')
    oParser.add_option('-H', '--header', action='store_true', default=False, help='Header')
    oParser.add_option('-U', '--unquoted', action='store_true', default=False, help='No handling of quotes in CSV file')
    (options, args) = oParser.parse_args()

    if options.separator == r'\t':
        options.separator = '\t'
    if len(args) == 0:
        oParser.print_help()
        print('')
        print('  %s' % __description__)
        return
    elif len(args) == 1:
        files = ['']
    else:
        files = ExpandFilenameArguments(args[1:])
    CSVCut(args[0], files, options)

if __name__ == '__main__':
    Main()
