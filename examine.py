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

def countOccurens(data):
	few = []
	for i in range(10000):
		#print ips[i]
		if i != 0:
			few.append(ips[i])


	count = Counter(few)

	mostOccurences =  max(few, key=few.count)
	print str(mostOccurences) + " occurs " + str(count[mostOccurences])




def find_service_types(data):
	types = []
	types_num = {'service': 0,'chg': 0, 'dns': 0, 'ntp': 0, 'qotd': 0, 'snmp': 0, 'ssdp': 0}
	types_packets = {'service': 0,'chg': 0, 'dns': 0, 'ntp': 0, 'qotd': 0, 'snmp': 0, 'ssdp': 0}	
	types_duration = {'service': 0,'chg': 0, 'dns': 0, 'ntp': 0, 'qotd': 0, 'snmp': 0, 'ssdp': 0}	
	for d in data:
		if d[SERVICE] == 'service':
			continue
		if not d[SERVICE] in types:
			types.append(d[SERVICE])
		types_num[d[SERVICE]] = types_num[d[SERVICE]] +1
		types_packets[d[SERVICE]] = int(types_packets[d[SERVICE]]) + int(d[PACKETS])
		types_duration[d[SERVICE]] = int(types_duration[d[SERVICE]]) + int(d[DURATION])



	return types_num, types_packets, types_duration

def calc_service_types(data):

	print '\n'
	tn, tp, td = find_service_types(data)
	print tn
	print tp
	print td

	indices = {'chg', 'dns', 'ntp', 'qotd', 'snmp','ssdp'}

	for i in indices:
		print i
		if tn[i] != 0:
			print "\tNum " + str(tn[i])
			print "\tPercentage " + str( tn[i] / len(data) )
			print "\tPackets/num " + str( tp[i]/tn[i] )
			print "\tDuration/num " + str( td[i]/tn[i] )


def occurence_nl(data):
	count =0
	for d in data:
		if d[COUNTRY] == NL:
			count +=1
	return count

def occurence(data, country):
	count =0
	for d in data:
		if d[COUNTRY] == country:
			count +=1
	return count	

def print_first(data, x):
	print "\n\nFirst few data entries ("+ str(x) + ")"
	for i in range(x):
		print data[i]


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
		#print "\tBiggest: " + key + ", size: " + str(biggest)	


def is_nl(data_entry):
	if data_entry[COUNTRY] == NL:
		return True
	return False

#Returns a sorted list of all countries and there number of occurences
def get_countries(data):
	l = {}
	for entry in data:
		key = entry[COUNTRY]
		try:
			l[key] = l[key] +1
		except KeyError:
			l[key] = 1

	return sorted(l.items(),key=lambda x:-x[1])

def print_countries(data):
	print "\n\nCountries"
	array = get_countries(data)
	for key, num in array:
		#print "\t" + key + "\t\t" + str(array[key])
		print "\t{0:45} {1:10}".format(key, num)
	print "\n"

def parse_year(date):
	if date == 'stop-time':
		return 2013
	return date[:4]

def last_year(data):
	year = 2013
	for entry in data:
		entry_year = parse_year(entry[STOP_TIME])
		if year < entry_year:
			year = entry_year
	return int(year)

def print_years(data):
	print "\nYEARS"
	print "\tLast year: " + str(last_year(data))
	print "\tFirst year"


def get_as(data, provider):
	as_list = []
	for entry in data:
		if entry[AS] == provider:
			as_list.append(entry)
	return as_list

def get_packets_duration_protocol(data, protocol):
	packets = []
	duration = []
	for entry in data:
		if entry[SERVICE] == protocol:
			packets.append(int(entry[PACKETS]))
			duration.append(int(entry[DURATION]))
	return packets, duration





def show_pd_analysis(data, provider, title = None):
	ziggo_data = get_as(data, provider)
	DNSpackets, DNSduration = get_packets_duration_protocol(ziggo_data, 'dns')
	CHGpackets, CHGduration = get_packets_duration_protocol(ziggo_data, 'chg')
	NTPpackets, NTPduration = get_packets_duration_protocol(ziggo_data, 'ntp')
	QOTDpackets, QOTDduration = get_packets_duration_protocol(ziggo_data, 'qotd')
	SNMPpackets, SNMPduration = get_packets_duration_protocol(ziggo_data, 'snmp')
	SSDPpackets, SSDPduration = get_packets_duration_protocol(ziggo_data, 'ssdp')


	if title == None:
		title = provider

	seriePackets = { 'dns' : pd.Series(DNSpackets), 'chg': pd.Series(CHGpackets), 'ntp' : pd.Series(NTPpackets)
		, 'qotd' : pd.Series(QOTDpackets), 'snmp' : pd.Series(SNMPpackets), 'ssdp' : pd.Series(SSDPpackets)}
	dfPackets = pd.DataFrame(seriePackets)

	serieDuration = { 'dns' : pd.Series(DNSduration), 'chg': pd.Series(CHGduration), 'ntp' : pd.Series(NTPduration)
		, 'qotd' : pd.Series(QOTDduration), 'snmp' : pd.Series(SNMPduration), 'ssdp' : pd.Series(SSDPduration)}
	dfDuration = pd.DataFrame(serieDuration)	


	sns.set_style("whitegrid")
	sns.set(font_scale=1.5)
	plt.figure()
	ax = sns.boxplot(data=dfPackets, palette="Set3")
	ax.set(xlabel='Protocol', ylabel='Packets')
	ax.set_title(title)


	plt.figure()
	ax = sns.boxplot(data=dfDuration, palette="Set3", )
	ax.set(xlabel='Protocol', ylabel= 'Duration (s)')
	ax.set_title(title)

	plt.figure()

def histogram_as(data, provider, title = None):
	providerData = get_as(data, provider)

	if title == None:
		title = provider

	tn, tp, td = find_service_types(providerData)

	indices = {'chg', 'dns', 'ntp', 'qotd', 'snmp','ssdp'}
	serie = { 'dns' : pd.Series(tn['dns']), 'chg': pd.Series(tn['chg']), 'ntp' : pd.Series(tn['ntp'])
		, 'qotd' : pd.Series(tn['qotd']), 'snmp' : pd.Series(tn['snmp']), 'ssdp' : pd.Series(tn['ssdp'])}
	df = pd.DataFrame(serie)

	sns.set_style("whitegrid")
	plt.figure()
	ax = sns.barplot(data=df, palette="Set3")
	ax.set(xlabel='Protocol', ylabel='Number of attacks')
	ax.set_title(title)


def test_analysis(data):
	#'AS8737 Koninklijke KPN N.V.'
	#'AS60781 LeaseWeb B.V.']
	providers = ['AS9143 Ziggo B.V.', 'AS8737 Koninklijke KPN N.V.'] 
	for provider in providers:
		show_pd_analysis(data, provider)
		#histogram_as(data, provider)
















print 'Loading data'
data, ips = load_file('/media/rico/OS_Install/Documents and Settings/Rico/Mijn documenten/MATLAB/combined.csv')
print 'Loaded data'


#analysis_as(data)
calc_service_types(data)
test_analysis(data)
#print_countries(data)
#print_years(data)
#calc_service_types(data)


#show_pd_analysis(data, 'AS9143 Ziggo B.V.')
#show_pd_analysis(data, 'AS60781 LeaseWeb B.V.')
#show_pd_analysis(data, 'AS8737 Koninklijke KPN N.V.')






print "Total data size: " + str(len(data))

#total = len(data)
#nl_count = occurence_nl(data)
#us_count = occurence(data, 'United States')
#print "US: " + str(us_count)

#print str(nl_count) + ", " + str(total)
#print nl_count / total

print_first(data, 2)

print "Showing data..."
plt.show()


print 'Closing application...'