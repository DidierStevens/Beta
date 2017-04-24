#!/usr/bin/env python

__description__ = 'Process command'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2017/04/24'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2013/08/29: start
  2013/08/30: continue
  2013/08/31: added options s and H
  2013/09/02: added [path] section
  2013/09/07: added datetime variables
  2013/09/09: continued InstantiateDateTimeVariable
  2013/10/31: added @file processing
  2014/01/31: added class cCommand
  2014/02/11: added option -w
  2014/08/31: added result logging
  2014/09/01: added csv log with results for file
  2014/10/02: added option -r
  2014/12/27: added time +d format
  2015/01/06: added option -N; added +whms time format
  2015/01/17: added [env] section
  2015/01/18: added man
  2015/02/25: added option -p
  2015/04/22: fix for re.sub backslash handling
  2015/06/16: added option -g
  2015/06/19: updated man
  2015/09/03: extra tests in SetPath; added !platform:win32! condition
  2015/09/04: updated man
  2015/09/13: added option -q
  2016/01/20: added VariableNameValue
  2017/04/24: added support for @ stdin

Todo:
"""

import optparse
import glob
import os
import csv
import re
import time
import collections
import datetime
import textwrap
import cPickle
import os
import sys

DEFAULT_SEPARATOR = ';'

def PrintManual():
    manual = '''
Manual:

process-command.py is a tool to help with the execution of command-line programs. It can execute these commands for a set of files or a set of rows in a CSV file.

The first argument is a text file with the commands to execute. This text file has 5 optional sections:
[path]
[env]
[begin]
[repeat]
[end]

A line that starts with # in the text file is a comment and is ignored.

The commands to execute for each file or row are place under [repeat]. If there are preliminary commands, they are placed under [begin]. Final commands are placed under [end].
[path] is used to add folders to the PATH environment variable, and [env] is used to declare environment variables.

Here is an example (command-filter.txt):
[path]
%ProgramFiles%\Wireshark
%ProgramFiles(x86)%\Wireshark
c:\Program Files\Wireshark

[begin]
mkdir temp

[repeat]
TSHARK.EXE -r %f% -w temp\%r%-10.20.30.0.pcap -Y "ip.addr == 10.20.30.0/24"

[end]
mergecap.EXE -F pcap -w 10.20.30.0.pcap temp\*.pcap
del /q temp\*.*
rmdir temp

Command: process-command.py command-filter.txt traffic*.pcap

This example executes Wireshark commands to extract all traffic from or to subnet 10.20.30.0/24 from a set of capture files (traffic*.pcap). The result is a new capture file: 10.20.30.0.pcap.

First process-command checks the PATH environment variable for the presence of a couple of Wireshark folders on Windows. If these folders are not in the PATH environment variable they are added to it, provided they exist. This permits the execution of Wireshark commands like tshark.exe and mergecap.exe without having to provide the full path. This is helpful when one doesn't know if Wireshark for Windows x86 or x64 is installed.

Then a temporary folder is created ([begin] section).

Then, for each file in the file set traffic*.pcap, the following command is executed ([repeat] section):
TSHARK.EXE -r %f% -w temp\%r%-10.20.30.0.pcap -Y "ip.addr == 10.20.30.0/24"
tshark is the command-line version of Wireshark, -r specifies the input file, -w the output file, and -Y is the display filter used to filter the input file. For each file in the file set traffic*.pcap, a set of variables are defined:
%f% is the full filename (with directory if present)
%b% is the base name: the filename without directory
%d% is the directory
%r% is the root: the filename without extension
%e% is the extension
So with -r %f% each file is processed by tshark. The filtered output is written to a new file in the temp directory: -w temp\%r%-10.20.30.0.pcap. This creates a new file starting with the same name as the input file and ending with -10.20.30.0.

Finally, all filtered files in the temp directory are merged into one file (with mergecap.exe), and the temp directory is deleted ([end] section).

Commands can be preceded by a condition, like this: !condition!command
The condition can be the platform. Platform can be win32, linux, cygwin or darwin.
Example of commands to erase a file on Windows or Linux:
!platform:win32!del test.txt
!platform:linux!rm test.txt

By default, variables %f%, %b%, %d%, %r% and %e% represent one file. But they can represent more than one file when using the group option (-g) and providing a number larger than 1.

One can also provide a CSV file instead of a set of files with option -c. The commands in the [repeat] section are executed for each row. Instead of using the file variables (%f%, %b%, ...) one uses the CSV variables: %v1%, %v2%, %v3%, ... These variables are instantiated for each row: %v1% is the first value in a row, %v2% is the second value in a row, ...
If the CSV files has a header row, use option -H. Option -s allows one to specify the separator used in the CSV file (; by default).
Option -q (quiet) disables output from process-command (but not the commands) to the console.

process-command can also be instructed to process new files: files it did not process before. To achieve this, use option -p processedfilesdb (you can choose your own filename for processedfilesdb). processedfilesdb is a pickle file containing all files processed by process-command.

To execute a command file without any input files or CSV file, use option -z.

To test a command file without actually executing the commands, use option -n.

When process-command runs, it creates 2 log files in the working directory to report all activities. A timestamped .log file is created containing all commands, and a timestamped .csv file is created containing all filenames with the result code of the executed command. To prevent the creation of these log files, use option -N.

The working directory can be specified with option -w.

For simple commands without having to create a command text file, use option -r and provide a single repeat command as the first argument.

Variables can be specified with option -v, like this example: -v PROXY=192.168.0.10. This defines the %PROXY% variable. To specify more than one variable, use the separator: -v PROXY=192.168.0.10;PRINTER=192.168.0.20.

process-command defines date/time variables which can be used, for example, to timestamp filenames. %time:YMD% for example is the current date: 20150118. One can use Y for Year, M for Month, D for Day, H for Hour, I for mInute and S for Second. An example if one needs to create a timestamped log file: %time:result-YMD-HIS.log%.
A future date/time can be calculated with +. This is an example for the date/time in 2 days: %time+2d:YMD-HIS%. One can add weeks (w), days (d), hours (h), minutes (m) or seconds (s).
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]

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

def Serialize(object, filename=None):
    try:
        fPickle = open(filename, 'wb')
    except:
        return False
    try:
        cPickle.dump(object, fPickle, cPickle.HIGHEST_PROTOCOL)
    except:
        return False
    finally:
        fPickle.close()
    return True

def DeSerialize(filename=None):
    if os.path.isfile(filename):
        try:
            fPickle = open(filename, 'rb')
        except:
            return None
        try:
            object = cPickle.load(fPickle)
        except:
            return None
        finally:
            fPickle.close()
        return object
    else:
        return None

class cCommand():
    def __init__(self, noexecute, separator, nologs, quiet):
        timestamp = Timestamp()
        self.filenameLog = 'log-commands-%s.log' % timestamp
        self.filenameCSV = 'log-commands-%s.csv' % timestamp
        self.noexecute = noexecute
        self.separator = separator
        self.nologs = nologs
        self.quiet = quiet

    def ExecuteAndLog(self, command, filename=''):
        line = IFF(self.noexecute, 'ECHO ' + command, command)
        if not self.quiet:
            print(line)
        if not self.nologs:
            f = open(self.filenameLog, 'a')
            f.write('%s: %s\n' % (Timestamp(), line))
            f.close()
        if not self.noexecute:
            result = os.system(command)
            if not self.nologs:
                f = open(self.filenameLog, 'a')
                f.write('%s: Result %s\n' % (Timestamp(), repr(result)))
                f.close()
                if filename != '':
                    f = open(self.filenameCSV, 'a')
                    f.write('%s\n' % self.separator.join([repr(result), filename]))
                    f.close()

def InstantiateDateTimeVariable(astring):
    oMatch = re.match(r'%time(\+(\d+[wdhms]))?:([^%]+)%', astring)
    if oMatch == None:
        return astring

    now = datetime.datetime.today()
    if oMatch.group(2) != None:
        if oMatch.group(2)[-1] == 'w':
            now += datetime.timedelta(weeks=int(oMatch.group(2)[:-1]))
        elif oMatch.group(2)[-1] == 'd':
            now += datetime.timedelta(days=int(oMatch.group(2)[:-1]))
        elif oMatch.group(2)[-1] == 'h':
            now += datetime.timedelta(hours=int(oMatch.group(2)[:-1]))
        elif oMatch.group(2)[-1] == 'm':
            now += datetime.timedelta(minutes=int(oMatch.group(2)[:-1]))
        elif oMatch.group(2)[-1] == 's':
            now += datetime.timedelta(seconds=int(oMatch.group(2)[:-1]))
    result = ''
    for c in oMatch.group(3):
        if c == 'Y':
            result += '%04d' % now.year
        elif c == 'M':
            result += '%02d' % now.month
        elif c == 'D':
            result += '%02d' % now.day
        elif c == 'H':
            result += '%02d' % now.hour
        elif c == 'I':
            result += '%02d' % now.minute
        elif c == 'S':
            result += '%02d' % now.second
        else:
            result += c
    return result

def InstantiateDateTimeVariables(astring):
    astring = ''.join([InstantiateDateTimeVariable(s) for s in re.split(r'(%time:[^%]+%)', astring)])
    return ''.join([InstantiateDateTimeVariable(s) for s in re.split(r'(%time\+\d+[wdhms]:[^%]+%)', astring)])

def VariableNameValue(data):
    position = data.find('=')
    if position == -1:
        return None, None
    return data[:position], data[position + 1:]

class cVariables():
    def __init__(self, variablesstring='', separator=DEFAULT_SEPARATOR):
        self.dVariables = {}
        if variablesstring == '':
            return
        for variable in variablesstring.split(separator):
            name, value = VariableNameValue(variable)
            self.dVariables[name] = value

    def SetVariable(self, name, value):
        self.dVariables[name] = value

    def Instantiate(self, astring):
        for key, value in self.dVariables.items():
            astring = astring.replace('%' + key + '%', value)
        return astring

def File2Strings(filename):
    try:
        if filename == '':
            f = sys.stdin
        else:
            f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        if f != sys.stdin:
            f.close()

def ParseCommand(filecommand, isRepeatCommand):
    path = []
    env = []
    begin = []
    repeat = []
    end = []
    if isRepeatCommand:
        repeat.append(filecommand)
    else:
        select = None
        for line in File2Strings(filecommand):
            if line.strip().startswith('#'):
                pass
            elif line == '[path]':
                select = path
            elif line == '[env]':
                select = env
            elif line == '[begin]':
                select = begin
            elif line == '[repeat]':
                select = repeat
            elif line == '[end]':
                select = end
            else:
                select.append(line)
    return path, env, begin, repeat, end

def EnvironmentVariableInstantiate(astring):
    for varname in os.environ:
        revarname = re.compile('%' + varname + '%', re.IGNORECASE)
        if revarname.search(astring):
            astring = revarname.sub(lambda x: os.environ[varname], astring)
    return astring

def SetPath(paths):
    pathModified = False
    pathenv = os.environ['PATH']
    for path in [x.strip() for x in paths]:
        if path != '':
            path = EnvironmentVariableInstantiate(path)
            if not '%' in path and os.path.isdir(path) and not path in pathenv:
                pathenv += ';' + path
                pathModified = True
    if pathModified:
        os.environ['PATH'] = pathenv
        print pathenv

def SetEnv(env):
    for var in env:
        result = var.split('=')
        if len(result) != 2:
            print('Error [env]: %s' % env)
        else:
            os.environ[result[0].strip()] = result[1].strip()

def InstantiateVariables(oVariables, astring):
    return InstantiateDateTimeVariables(oVariables.Instantiate(astring))

#!platform:linux!rm file
def ConditionalCommand(command):
    if not command.startswith('!'):
        return command
    position = command.find('!', 1)
    if position == -1:
        return command
    condition = command[1:position]
    if not condition.startswith('platform:'):
        return command
    command = command[position+1:]
    platform = sys.platform
    if platform.startswith('linux'):
        platform = platform[0:5]
    if platform == condition[9:]:
        return command
    else:
        return ''

def ProcessCommand(command, oCommand, oVariables, row=[]):
    command = ConditionalCommand(command)
    if command == '':
        return
    for iter in range(len(row)):
        command = command.replace('%v' + str(iter + 1) + '%', row[iter])
    command = InstantiateVariables(oVariables, command)
    oCommand.ExecuteAndLog(command)

def ProcessCommandFile(command, filenames, oCommand, oVariables):
    command = ConditionalCommand(command)
    if command == '':
        return

    lf = []
    lb = []
    ld = []
    lr = []
    le = []
    for filename in filenames:
        basename = os.path.basename(filename)
        root, extension = os.path.splitext(basename)
        lf.append(filename)
        lb.append(basename)
        ld.append(os.path.dirname(filename))
        lr.append(root)
        le.append(extension)

    oFilenameVariables = cVariables()
    oFilenameVariables.SetVariable('f', ' '.join(lf))
    oFilenameVariables.SetVariable('b', ' '.join(lb))
    oFilenameVariables.SetVariable('d', ' '.join(ld))
    oFilenameVariables.SetVariable('r', ' '.join(lr))
    oFilenameVariables.SetVariable('e', ' '.join(le))

    command = InstantiateVariables(oVariables, command)
    command = oFilenameVariables.Instantiate(command)
    oCommand.ExecuteAndLog(command, filename)

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

def ProcessCommandFiles(filecommand, files, options):
    try:
        files = ExpandFilenameArguments(files)
    except Exception as e:
        print(e)
        return

    oCommand = cCommand(options.noexecute, options.separator, options.nologs, options.quiet)
    oVariables = cVariables(options.variables, options.separator)
    path, env, commandBegin, commandRepeat, commandEnd = ParseCommand(filecommand, options.repeat)
    SetPath(path)
    SetEnv(env)
    if options.processedfilesdb != None:
        data = DeSerialize(options.processedfilesdb)
        if data == None:
            dProcessedFiles = {}
        else:
            dProcessedFiles = data[0]
    else:
        dProcessedFiles = {}
    for command in commandBegin:
        ProcessCommand(command, oCommand, oVariables)
    filenames = []
    for filename in files:
        if not filename in dProcessedFiles:
            filenames.append(filename)
            dProcessedFiles[filename] = Timestamp()
        if len(filenames) == options.group:
            for command in commandRepeat:
                ProcessCommandFile(command, filenames, oCommand, oVariables)
            filenames = []
    if filenames != []:
        for command in commandRepeat:
            ProcessCommandFile(command, filenames, oCommand, oVariables)
    for command in commandEnd:
        ProcessCommand(command, oCommand, oVariables)
    if options.processedfilesdb != None:
         Serialize([dProcessedFiles], options.processedfilesdb)

def ProcessCommandCSV(filecommand, options):
    oCommand = cCommand(options.noexecute, options.separator, options.nologs, options.quiet)
    oVariables = cVariables(options.variables, options.separator)
    path, env, commandBegin, commandRepeat, commandEnd = ParseCommand(filecommand, options.repeat)
    SetPath(path)
    SetEnv(env)
    for command in commandBegin:
        ProcessCommand(command, oCommand, oVariables)
    reader = csv.reader(open(options.csv, 'rb'), delimiter=options.separator, skipinitialspace=True)
    countRows = 0
    for row in reader:
        countRows += 1
        if not options.header or options.header and countRows > 1:
            for command in commandRepeat:
                ProcessCommand(command, oCommand, oVariables, row)
    for command in commandEnd:
        ProcessCommand(command, oCommand, oVariables)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] file-command|repeat-command [file] ...\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-n', '--noexecute', action='store_true', default=False, help='do no execute the command')
    oParser.add_option('-c', '--csv', default='', help='CSV file with variables')
    oParser.add_option('-v', '--variables', default='', help='define variables')
    oParser.add_option('-s', '--separator', default=DEFAULT_SEPARATOR, help='set the separator (dedault ;)')
    oParser.add_option('-H', '--header', action='store_true', default=False, help='the CSV file has a header')
    oParser.add_option('-z', '--zeroinput', action='store_true', default=False, help='zero input: process without input')
    oParser.add_option('-w', '--workingdirectory', default='', help='set the working directory')
    oParser.add_option('-r', '--repeat', action='store_true', default=False, help='use repeat-command')
    oParser.add_option('-N', '--nologs', action='store_true', default=False, help='do no create log files')
    oParser.add_option('-p', '--processedfilesdb', default=None, help='file pointing to database (pickle) of processed files')
    oParser.add_option('-g', '--group', type=int, default=1, help='number of files to group for one command (default 1)')
    oParser.add_option('-q', '--quiet', action='store_true', default=False, help='do no output to the console')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if options.csv == '' and not options.zeroinput and len(args) < 2 or options.csv != '' and len(args) != 1 or options.zeroinput and len(args) != 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    if options.workingdirectory != '':
        os.chdir(options.workingdirectory)
    if options.csv == '':
        ProcessCommandFiles(args[0], args[1:], options)
    elif options.zeroinput:
        ProcessCommandFiles(args[0], [], options)
    else:
        ProcessCommandCSV(args[0], options)

if __name__ == '__main__':
    Main()
