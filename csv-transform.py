#!/usr/bin/env python

__description__ = 'Tool to transform csv values'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2017/12/28'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/01/08: start
  2014/05/15: continue
  2014/08/04: added option unquoted
  2014/08/13: changed skipinitialspace
  2015/08/13: added support for \t separator
  2016/04/22: added support for writing .gz output
  2016/04/25: added option --script
  2017/12/14: merged with csv-calc.pt; added option --execute; added man
  2017/12/28: fix for option header if file is stdin

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
import re
import textwrap

QUOTE = '"'

def PrintManual():
    manual = r'''
Manual:

This tool takes one or more CSV files as input and produces a new CSV file with one column transformed via a Python expression.

This Python script was developed with Python 2.7 and tested with Python 2.7 and 3.5.

The arguments to this command are a column, an expression and one or more filenames. If a provided file is a gzip compressed file (extension .gz), csv-transform.py will decompress the content of the file. Wildcards are supported (like data*.csv) and 'here-files' can be used. A here-file is a text file that contains a list of filenames. Each filename must be written on a separate line. Here-files are identified by prefixing their filename with a '@' characters, like this: @documents.txt
When no filename is provided as argument, input is read from stdin.

The expression is a Python expression that calls function R() to access fields necessary in the calculation performed by the expression.
The provided column's values are replaced by the evaluated expression.

Let's take the following CSV file as example 1:
200;answer
206;answer
301;redirect
302;redirect
303;redirect
304;redirect
400;client error
401;client error
402;client error
403;client error
404;client error

This file has 11 rows, each with 2 fields (character ; is the field separator). There is no header row.

We will now run this script to replace the second column by the string length of the column's values.

Running the following command on this CSV file:
csv-transform.py 1 "len(R(1))" example-1.csv

produces the following output:

200;6
206;6
301;8
302;8
303;8
304;8
400;12
401;12
402;12
403;12
404;12

Each value in the second column is replaced by the string length of the original value.

Use option -a to leave the column's values intact, and to insert the new value after the column.
Example:
csv-transform.py -a 1 "len(R(1))" example-1.csv

200;answer;6
206;answer;6
301;redirect;8
302;redirect;8
303;redirect;8
304;redirect;8
400;client error;12
401;client error;12
402;client error;12
403;client error;12
404;client error;12

Use option -b to leave the column's values intact, and to insert the new value before the column.
Example:
csv-transform.py -b 1 "len(R(1))" example-1.csv

200;6;answer
206;6;answer
301;8;redirect
302;8;redirect
303;8;redirect
304;8;redirect
400;12;client error
401;12;client error
402;12;client error
403;12;client error
404;12;client error

The expression can reference more than one column:
csv-transform.py -a 1 "len(R(0))+len(R(1))" example-1.csv

200;answer;9
206;answer;9
301;redirect;11
302;redirect;11
303;redirect;11
304;redirect;11
400;client error;15
401;client error;15
402;client error;15
403;client error;15
404;client error;15

csv-transform.py can also handle CSV files with a header, like this file: example-2.csv

Code;Type
200;answer
206;answer
301;redirect
302;redirect
303;redirect
304;redirect
400;client error
401;client error
402;client error
403;client error
404;client error

By default, csv-transform.py does not assume the provided input files have headers. To recognize the first row of each input file as a header row, use option -H, like this:

csv-transform.py -H Type "len(R(1))" example-2.csv

Code;Type
200;6
206;6
301;8
302;8
303;8
304;8
400;12
401;12
402;12
403;12
404;12

When option -a or -b is used, the title of the column is "New Column".
Example:

csv-transform.py -H -a Type "len(R(1))" example-2.csv

Code;Type;New Column
200;answer;6
206;answer;6
301;redirect;8
302;redirect;8
303;redirect;8
304;redirect;8
400;client error;12
401;client error;12
402;client error;12
403;client error;12
404;client error;12

To choose another column title, use option -n, like this:

csv-transform.py -H -a -n "Total length" Type "len(R(1))" example-2.csv

Code;Type;Total length
200;answer;6
206;answer;6
301;redirect;8
302;redirect;8
303;redirect;8
304;redirect;8
400;client error;12
401;client error;12
402;client error;12
403;client error;12
404;client error;12

If the Python expression requires functions or modules not provided by Python by default, you can use option -S and -e.
Option -S takes a filename: a script to be loaded by csv-transform.py
Option -e takes a statement: a Python statement to be executed (for example -e "import time").

By default, csv-transform.py assumes that the field separator is the ; character. You can use option -s to provide another separator character. To use a TAB character as separator, use \\t.

By default, the output produced by csv-transform.py is printed to stdout. It can be written to a file using option -o, for example -o report.txt to write the report to file report.txt.

When a field contains a separator character that is not a separator, the field must be properly quoted, like this: 200;"ans;wer".
csv-transform.py handles quoted fields properly, but this can be supressed using option -U. When option -U is used, quotes have no special meaning.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

def PadLeft(value, length, padchar=' '):
    while len(value) < length:
        value = padchar + value
    return value

def PadRight(value, length, padchar=' '):
    while len(value) < length:
        value = value + padchar
    return value

def Replace(value, old, new):
    return value.replace(old, new)

def RE(regex, value):
    oMatch = re.search(regex, value)
    if not oMatch:
        return ''
    if len(oMatch.groups()) > 0:
        return oMatch.groups()[0]
    return oMatch.group()

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
    if isinstance(value, str):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if separator in value or value == '':
        return quote + value + quote
    else:
        return value

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

def Print(line, f):
    if f == None:
        print(line)
    else:
        f.write(line + '\n')

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

def QuoteString(value):
    if isinstance(value, str):
        if "'" in value:
            return 'r"%s"' % value
        else:
            return "r'%s'" % value
    else:
        return value

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

def ConvertHeaderToIndex(header, separator, columns):
    try:
        result = []
        for column in columns.split(separator):
            result.append(header.index(column))
        return result
    except:
        return None

def GetRowValue(row, column, headerrow):
    if isinstance(column, int):
        rowindex = column
    else:
        rowindex = headerrow.index(column)
    if rowindex >= len(row):
        return ''
    else:
        return row[rowindex]

def Transform(columnTransform, expression, files, options):
    FixPipe()
    if not options.headers:
        columnIndexTransform = int(columnTransform)

    if options.script != '':
        exec(open(options.script, 'r').read(), globals(), globals())

    if options.execute != '':
        exec(options.execute, globals())

    if options.output:
        if options.output.endswith('.gz'):
            fOut = gzip.GzipFile(options.output, 'w')
        else:
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
            fIn = open(file, 'r')
        reader = csv.reader(fIn, delimiter=options.separator, skipinitialspace=False, quoting=IFF(options.unquoted, csv.QUOTE_NONE, csv.QUOTE_MINIMAL))
        firstRow = True
        headerrow = None
        for row in reader:
            if options.headers and firstRow:
                firstRow = False
                headerrow = row
                lColumnTransform = ConvertHeaderToIndex(row, options.separator, columnTransform)
                if lColumnTransform == None or len(lColumnTransform) != 1:
                   print('Column %s not found in file %s' % (columnTransform, file))
                   return
                columnIndexTransform = lColumnTransform[0]
                if not headerPrinted:
                    if options.after:
                        Print(MakeCSVLine(row[0:columnIndexTransform + 1] + [options.new] + row[columnIndexTransform + 1:], options.separator, QUOTE), fOut)
                    elif options.before:
                        Print(MakeCSVLine(row[0:columnIndexTransform] + [options.new] + row[columnIndexTransform:], options.separator, QUOTE), fOut)
                    else:
                        Print(MakeCSVLine(row, options.separator, QUOTE), fOut)
                    headerPrinted = True
            else:
                R = lambda column: GetRowValue(row, column, headerrow)
                if options.after:
                    Print(MakeCSVLine(row[0:columnIndexTransform + 1] + [eval(expression)] + row[columnIndexTransform + 1:], options.separator, QUOTE), fOut)
                elif options.before:
                    Print(MakeCSVLine(row[0:columnIndexTransform] + [eval(expression)] + row[columnIndexTransform:], options.separator, QUOTE), fOut)
                else:
                    Print(MakeCSVLine(row[0:columnIndexTransform] + [eval(expression)] + row[columnIndexTransform + 1:], options.separator, QUOTE), fOut)
        if fIn != sys.stdin:
            fIn.close()

    if fOut != None:
        fOut.close()

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] column expression [[@]files]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-s', '--separator', default=';', help='Separator character (default ;)')
    oParser.add_option('-o', '--output', help='Output to file')
    oParser.add_option('-H', '--headers', action='store_true', default=False, help='Headers')
    oParser.add_option('-a', '--after', action='store_true', default=False, help='Insert after column')
    oParser.add_option('-b', '--before', action='store_true', default=False, help='Insert before column')
    oParser.add_option('-n', '--new', default='New Column', help='New column title')
    oParser.add_option('-U', '--unquoted', action='store_true', default=False, help='no handling of quotes in CSV file')
    oParser.add_option('-S', '--script', default='', help='Script with definitions to include')
    oParser.add_option('-e', '--execute', default='', help='Commands to execute')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if options.separator == r'\t':
        options.separator = '\t'
    if len(args) == 2:
        files = ['']
    elif len(args) < 3:
        oParser.print_help()
        print('')
        print('  %s' % __description__)
        return
    else:
        files = ExpandFilenameArguments(args[2:])
    if options.after and options.before:
        print('Error: options after and before are mutualy exclusive')
        return
    Transform(args[0], args[1], files, options)

if __name__ == '__main__':
    Main()
