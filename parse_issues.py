#!/usr/bin/env python

import json


j = json.load(open("msfissues.txt"))
    
for i in j:
    print(i)
