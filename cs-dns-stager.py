#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Get Cobalt Strike DNS beacon'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2021/05/30'

import string
import sys
import dns.resolver

#https://stackoverflow.com/questions/2267362/how-to-convert-an-integer-to-a-string-in-any-base
def int2base(x, base, leading=0):
    digs = string.ascii_letters

    if x < 0:
        sign = -1
    else:
        sign = 1

    x *= sign
    digits = []

    while x:
        digits.append(digs[int(x % base)])
        x = int(x / base)

    while len(digits) < leading:
        digits.append(digs[0])

    if sign < 0:
        digits.append('-')

    digits.reverse()

    return ''.join(digits)

def Main(ipv4, filename):
    counter = 0
    alltext = ''
    oResolver = dns.resolver.Resolver()
    oResolver.nameservers = [ipv4]
    while True:
        query = int2base(counter, 26, 3)[::-1] + '.stage.whatever.'
        print(query)
        try:
            text = oResolver.resolve(query, 'txt')[0].to_text().strip('"')
        except:
            break
        if text == '':
            break
        counter += 1
        alltext += text
    with open(filename, 'w') as fOut:
        fOut.write(alltext)

if __name__ == '__main__':
    if len(sys.argv) == 3:
        Main(sys.argv[1], sys.argv[2])
    else:
        print('Usage: cs-dns-stager.py IPv4 filename.txt')

