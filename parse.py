#!/usr/bin/python

import jsparser
import sys

fn = sys.argv[1]
p = jsparser.parse(open(fn).read(), fn)

def typeof(n):
    return jsparser.tokens[n.type_]

def scan_for_require(n):
    print typeof(n)
    if n.type_ in (jsparser.SCRIPT,):
        for sn in n:
            scan_for_require(sn)


scan_for_require(p)
