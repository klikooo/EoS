#!/usr/bin/env python
from __future__ import division
from collections import Counter
from collections import OrderedDict

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import pandas as pd
import csv

class ContinueLoop(Exception): pass


DATE		= 0
SENSOR_ID	= 1
SERVICE 	= 2
TARGET_IP	= 3
COUNTRY 	= 4
AS 			= 5
HOSTNAME 	= 6
START_TIME 	= 7
STOP_TIME 	= 8
DURATION 	= 9
PACKETS 	= 10

NL = 'Netherlands'



def load_file(file):
	data = []
	ips= []
	with open(file, 'rb') as csvfile:
		spamreader = csv.reader(csvfile, delimiter='|')
		for row in spamreader:
			data.append(row)
			ips.append(row[TARGET_IP])
	return data,ips

def print_countries(data):
	print "\n\nCountries"
	array = get_countries(data)
	for key, num in array:
		#print "\t" + key + "\t\t" + str(array[key])
		print "\t{0:45} {1:10}".format(key, num)
	print "\n"



	
print 'Loading data'
data, ips = load_file('/media/rico/OS_Install/Documents and Settings/Rico/Mijn documenten/MATLAB/combined.csv')
print 'Loaded data'
sns.set(font_scale=1.3)


def get_as(data, provider):
	l = []
	for d in data:
		if d[AS] == provider:
			l.append(d)
	return l

def get_year(date):
	return date[:4]

def get_month(date):
	return date[5:7]

def split_in_years(data):
	l= {'2013' : [], '2014' : [], '2015': []}
	for d in data:
		date = d[START_TIME]
		l[get_year(date)].append(d)
	return l

def count_as(data, filterFunc = None):
	l = {}
	for d in data:
		key = d[AS]
		if key == 'as':
			continue

		#apply a filter function
		if filterFunc != None and not filterFunc(d):
			continue
		try:
			l[key] = l[key] +1
		except KeyError:
			l[key] = 1
	return sorted(l.items(),key=lambda x:-x[1])

def analysis_as(data, filterFunc= None):
	l = count_as(data, filterFunc)

	print '\nAS:'
	for key, num in l:
		print "{0:50} {1:20}".format(key, num)

def avg_size(data, type):
	if len(data) == 0: 
		return 0
	sum =0
	for d in data:
		sum += int(d[type])
	return sum / len(data)

def monthly(data):
	l = {1: [], 2: [], 3: [], 4: [], 5: [], 6: [], 7: [], 8: [], 9: [], 10: [], 11: [], 12: []}
	for d in data:
		date= d[DATE]
		l[int(get_month(date))].append(d)
	for month in range(1,13):
		print month, " packets: ", avg_size(l[month], PACKETS), "duration: ", avg_size(l[month], DURATION), "attacks: ", len(l[month])

print "Total data size: " + str(len(data))


l = get_as(data, 'AS7018 AT&T Services<comma> Inc.')
#l = get_as(data, 'AS9143 Ziggo B.V.')
#l = get_as(data, 'AS7018 AT&T Services<comma> Inc.')
dates = split_in_years(l)
# print '2013 ', len(dates['2013']), ", ", avg_size(dates['2013'], PACKETS), " ", avg_size(dates['2013'], DURATION)
# print '2014 ', len(dates['2014']), ", ", avg_size(dates['2014'], PACKETS), " ", avg_size(dates['2014'], DURATION)
# print '2015 ', len(dates['2015']), ", ", avg_size(dates['2015'], PACKETS), " ", avg_size(dates['2015'], DURATION)


print "Num attacks: ", len(dates['2015'])
monthly(dates['2013'])
monthly(dates['2014'])
monthly(dates['2015'])


print "Showing data..."
plt.show()


print 'Closing application...'