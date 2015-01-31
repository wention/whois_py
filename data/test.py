#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
import traceback
import json

def test(f):
    try:
        fd = open(f,"rb")
        data = fd.read()
        obj = json.loads(data)
    except:
        print traceback.format_exc()

if __name__ == "__main__":
    test(sys.argv[1])
