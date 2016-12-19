#!/usr/bin/env python

__description__ = 'Tool to lookup value for CSV files'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2016/12/19'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2012/12/10: start
  2012/12/24: fixed pipe bug
  2014/01/21: added columnValue
  2014/01/26: added option exclude
  2014/01/30: added option found
  2014/08/13: added option unquoted, changed skipinitialspace
  2015/08/13: added support for \t separator
  2016/04/22: added support for .gz
  2016/12/18: added ParseOptionSeparator, added option -p
  2016/12/19: added option useheader

Todo:
"""

import csv
import optparse
import signal
import os
import gzip
import cStringIO

QUOTE = '"'

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

def BuildDictionary(fileLookup, columnLookup, separator, header, ignorecase, unquoted):
    if ignorecase:
        Function = str.lower
    else:
        Function = lambda x:x
    dLookup = {}
    fIn = open(fileLookup, 'rb')
    reader = csv.reader(fIn, delimiter=separator, skipinitialspace=False, quoting=IFF(unquoted, csv.QUOTE_NONE, csv.QUOTE_MINIMAL))
    if header:
        reader.next()
    for row in reader:
        if not Function(row[columnLookup]) in dLookup:
            dLookup[Function(row[columnLookup])] = row
    fIn.close()
    return dLookup

def SelectValuesFromRow(row, columns):
    result = []
    for column in columns:
        if column < len(row):
            result.append(row[column])
        else:
            result.append('')
    return result

def Lookup(key, dictionary, partial):
    if key in dictionary:
        return (dictionary[key], 'FULLMATCH', '')
    if partial == '':
        return (None, '', '')
    splitkey = key.split(partial[0])
    if partial[1] == 'l':
        splitkey = splitkey[1:]
    else:
        splitkey = splitkey[:-1]
    minimumlength = 1
    if partial[2:] !='':
        minimumlength = int(partial[2:])
    while len(splitkey) >= minimumlength:
        partialkey = partial[0].join(splitkey)
        if partialkey in dictionary:
            return (dictionary[partialkey], str(len(splitkey)), partialkey)
        if partial[1] == 'l':
            splitkey = splitkey[1:]
        else:
            splitkey = splitkey[:-1]
    return (None, '', '')

def CSVLookup(fileCSV, columnCSV, headers, fileLookup, columnLookup, columnValues, fileOutput, options):
    dLookup = BuildDictionary(fileLookup, columnLookup, options.separator[1], options.headers, options.ignorecase, options.unquoted)

    if options.replace:
        replace = 0
    else:
        replace = 1
    if options.ignorecase:
        Function = str.lower
    else:
        Function = lambda x:x
    if os.path.splitext(fileCSV)[1].lower() == '.gz':
        fIn = gzip.GzipFile(fileCSV, 'rb')
    else:
        fIn = open(fileCSV, 'rb')
    if fileOutput.endswith('.gz'):
        fOut = gzip.GzipFile(fileOutput, 'w')
    else:
        fOut = open(fileOutput, 'w')
    reader = csv.reader(fIn, delimiter=options.separator[0], skipinitialspace=False, quoting=IFF(options.unquoted, csv.QUOTE_NONE, csv.QUOTE_MINIMAL))
    if options.headers:
        reader.next()
        fOut.write(MakeCSVLine(headers, options.separator[2], QUOTE) + '\n')
    for row in reader:
        matchedrow, match, partialkey = Lookup(Function(row[columnCSV]), dLookup, options.partial)
        if matchedrow != None:
            if options.found:
                value = ['1']
            else:
                value = SelectValuesFromRow(matchedrow, columnValues)
        elif options.exclude:
            value = None
        else:
            if options.found:
                value = ['0']
            else:
                value = map(lambda x:'', columnValues)
        if value != None:
            if options.partial != '':
                value.append(match)
                value.append(partialkey)
            out = row[0:columnCSV + replace] + value + row[columnCSV + 1:]
            fOut.write(MakeCSVLine(out, options.separator[2], QUOTE) + '\n')
    fIn.close()
    fOut.close()

def GetHeader(file, useheader, separator, unquoted):
    if useheader != '':
        fIn = cStringIO.StringIO(useheader)
    elif os.path.splitext(file)[1].lower() == '.gz':
        fIn = gzip.GzipFile(file, 'rb')
    else:
        fIn = open(file, 'rb')
    reader = csv.reader(fIn, delimiter=separator, skipinitialspace=False, quoting=IFF(unquoted, csv.QUOTE_NONE, csv.QUOTE_MINIMAL))
    header = reader.next()
    fIn.close()
    return header

def ConvertHeaderToIndex(file, useheader, separator, columns, unquoted):
    try:
        header = GetHeader(file, useheader, separator, unquoted)
        result = []
        for column in columns.split(separator):
            result.append(header.index(column))
        return result
    except:
        return None

def Process(fileCSV, columnCSV, fileLookup, columnLookup, columnValue, fileOutput, options):
    FixPipe()
    if options.headers:
        inputuseheader = ''
        lookupuseheader = ''
        if options.useheader != '':
            if options.useheader[0] == 'l':
                lookupuseheader = options.useheader[2:]
            else:
                inputuseheader = options.useheader[2:]
        lColumnCSV = ConvertHeaderToIndex(fileCSV, inputuseheader, options.separator[0], columnCSV, options.unquoted)
        if lColumnCSV == None or len(lColumnCSV) != 1:
            print('Column %s not found in file %s' % (columnCSV, fileCSV))
            return
        iColumnCSV = lColumnCSV[0]
        lColumnLookup = ConvertHeaderToIndex(fileLookup, lookupuseheader, options.separator[1], columnLookup, options.unquoted)
        if lColumnLookup == None or len(lColumnLookup) != 1:
            print('Column %s not found in file %s' % (columnLookup, fileLookup))
            return
        iColumnLookup = lColumnLookup[0]
        headersCSV = GetHeader(fileCSV, inputuseheader, options.separator[0], options.unquoted)
        headersLookup = GetHeader(fileLookup, lookupuseheader, options.separator[1], options.unquoted)
        if options.found:
            headersInsert = [columnValue]
            lColumnValue = []
        else:
            lColumnValue = ConvertHeaderToIndex(fileLookup, lookupuseheader, options.separator[1], columnValue, options.unquoted)
            if lColumnValue == None or len(lColumnValue) == 0:
                print('Column %s not found in file %s' % (columnValue, fileLookup))
                return
            headersInsert = SelectValuesFromRow(headersLookup, lColumnValue)
        if options.replace:
            replace = 0
        else:
            replace = 1
        headers = headersCSV[0:iColumnCSV + replace] + headersInsert + headersCSV[iColumnCSV + 1:]
    else:
        iColumnCSV = int(columnCSV)
        iColumnLookup = int(columnLookup)
        lColumnValue = map(int, columnValue.split(options.separator[2]))
        headers = None
    CSVLookup(fileCSV, iColumnCSV, headers, fileLookup, iColumnLookup, lColumnValue, fileOutput, options)

def ParseOptionSeparator(separator, number):
    separator = separator.replace(r'\t', '\t')
    if len(separator) == 1:
        return [separator for i in range(number)]
    if len(separator) != number:
        print('Error: expected %d separators, %d were provided' % (number, len(separator)))
        return None
    return [c for c in separator]

def ParseOptionPartial(partial):
    if partial == '':
        return False
    if len(partial) == 1:
        print('Error: second character of option partial should be present')
        return True
    if not partial[1] in ['l', 'r']:
        print('Error: second character of option partial should be l or r')
        return True
    if len(partial) > 2:
        try:
            number = int(partial[2:])
            if number <= 0:
                print('Error: integer of option partial should be at least 1')
                return True
        except:
            print('Error: third character of option partial should be an integer')
            return True
    return False

def CheckOptionUseheader(useheader):
    if useheader == '':
        return False
    if useheader[0:2] not in ['i:', 'l:']:
        print('Error: option useheader should start with i: or l:')
        return True
    return False

def CheckOptions(options):
    options.separator = ParseOptionSeparator(options.separator, 3)
    if options.separator == None:
        return True
    if ParseOptionPartial(options.partial):
        return True
    if CheckOptionUseheader(options.useheader):
        return True
    return False

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] fileCSV columnCSV fileLookup columnLookup columnValue fileOutput\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-s', '--separator', default=';', help='separator character(s) (default ;)')
    oParser.add_option('-H', '--headers', action='store_true', default=False, help='files have headers')
    oParser.add_option('-r', '--replace', action='store_true', default=False, help='replace value')
    oParser.add_option('-i', '--ignorecase', action='store_true', default=False, help='ignore case')
    oParser.add_option('-e', '--exclude', action='store_true', default=False, help='exclude rows with no lookup value')
    oParser.add_option('-f', '--found', action='store_true', default=False, help='use indicator: was lookup successful or not')
    oParser.add_option('-p', '--partial', default='', help='settings for partial lookup')
    oParser.add_option('-U', '--unquoted', action='store_true', default=False, help='No handling of quotes in CSV file')
    oParser.add_option('--useheader', default='', help='Header to use for i(nput) or l(ookup) file')
    (options, args) = oParser.parse_args()

    if CheckOptions(options):
        return
    if len(args) != 6:
        oParser.print_help()
        print('')
        print('  %s' % __description__)
        return
    Process(args[0], args[1], args[2], args[3], args[4], args[5], options)

if __name__ == '__main__':
    Main()
