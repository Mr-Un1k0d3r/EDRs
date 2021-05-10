#!/usr/bin/python3

# Usage: python3 Parse.py > out.csv

from os import listdir
from os.path import isfile, join
import os,sys
import tabulate
mypath = '.'
onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
txtfiles = [f for f in onlyfiles if (".txt" in f)]
hooks = []
super = {}

for f in txtfiles:
	j = open(f, 'r')
	for i in j.readlines():
		z = i.split(' ')[0]
		if(not(z.strip() in hooks)):
			hooks.append(z.strip())
	# prepare array
hooks.sort()
		
for f in txtfiles:
	j = open(f, 'r')
	edr = f.split('.')[0]
	super[edr] = {}
	for h in hooks:
		super[edr][h.strip()] = "FALSE"
	for i in j.readlines():
		z = i.split(' ')[0]
		super[edr][z.strip()] = "TRUE"


header = "{},{}".format('EDR',','.join(hooks))
print(header)

for edr in super.keys():
	print('{},{}'.format(edr,','.join(super[edr].values())))
