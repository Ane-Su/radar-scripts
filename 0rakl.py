#!/usr/bin/env python3
"""
			--- by Yuri BlackTie ----
 	The orakl.py will run some queries and get data to input when running lokt.py scan group 
 			as asset update sources 
 			
 			Example: ./0rakl.py
"""
import requests
import simplejson as json
import json



aak=input('[?] Enter ApiAccessKey : ')
print(aak)
#accesskey = " "  

ask=input('[?] Enter ApiSecretKey : ')
print(ask)
#secretkey = " "




def api_auth():
	"""
	Sends API requests using the requests module 
	This checks the validity of the authentication API access and secret keys
	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/authenticationcheck"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	for url in url_api:
		r = requests.get(url, headers=headers)
		print(r.status_code)
		if r.status_code == 200:
			print ("[*] Authentication was successful")
			#print (r.text)
		#info = json.loads(r.decode("utf-8"))


def discoveryScanIds():
	"""
	Sends API requests using the requests module 
	This lists all the discoveryscan nodes + ids

	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/discoveryscans/simple"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	for url in url_api:
		r = requests.get(url, headers=headers)
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] Fetching all available DiscoveryScan Ids")
			rs = r.text
			res = json.loads(rs)
	print ("[-] Writing into file ./info/discoveryScanIds.txt\n")
	with open('./info/discoveryScanIds.txt', 'w') as f:
		for item in res:
			f.write(str(item) + '\n\n')



def discoveryScanNodeIds():
	"""
	Sends API requests using the requests module 
	This lists all the discoveryscan nodes + ids

	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/scannodes/discoveryScan"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	for url in url_api:
		r = requests.get(url, headers=headers)
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] Fetching all available DiscoveryScan Node Ids")
			rs = r.text
			res = json.loads(rs)
	print ("[-] Writing into file ./info/discoveryScanNodeIds.txt\n")
	with open('./info/discoveryScanNodeIds.txt', 'w') as f:
		for item in res:
			f.write(str(item) + '\n\n')


def systemScanNodeIds():
	"""
	Sends API requests using the requests module 
	This lists all the systemscan nodes + ids
	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/scannodes/systemscan"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	for url in url_api:
		s = '{"Name"'
		r = requests.get(url, headers=headers)
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] Fetching all available SystemScan Node Ids")
			rs = r.text
			res = json.loads(rs)
	print ("[-] Writing into file ./info/systemScanNodeIds.txt\n")
	with open('./info/systemScanNodeIds.txt', 'w') as f:
		for item in res:
			f.write(str(item) + '\n\n')


def webScanNodeIds():
	"""
	Sends API requests using the requests module 
	This lists all the webscan nodes + ids
	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/scannodes/webscan"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	for url in url_api:
		r = requests.get(url, headers=headers)
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] Fetching all available WebScan Node Ids")
			rs = r.text
			res = json.loads(rs)
	print ("[-] Writing into file ./info/webScanNodeIds.txt\n")
	with open('./info/webScanNodeIds.txt', 'w') as f:
		for item in res:
			f.write(str(item) + '\n\n')


def systemScanTemplateIds():
	"""
	Sends API requests using the requests module 
	This lists all the webscan templates + ids
	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/scantemplates/systemscan/simple"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	for url in url_api:
		r = requests.get(url, headers=headers)
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] Fetching all available SystemScan template Ids")
			rs = r.text
			res = json.loads(rs)
	print ("[-] Writing into file ./info/systemScanTemplateIds.txt\n")
	with open('./info/systemScanTemplateIds.txt', 'w') as f:
		for item in res:
			f.write(str(item) + '\n\n')



def webScanTemplateIds():
	"""
	Sends API requests using the requests module 
	This lists all the webscan templates + ids
	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/scantemplates/webscan/simple"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	for url in url_api:
		r = requests.get(url, headers=headers)
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] Fetching all available WebScan template Ids")
			rs = r.text
			res = json.loads(rs)
	print ("[-] Writing into file ./info/webScanTemplateIds.txt\n")
	with open('./info/webScanTemplateIds.txt', 'w') as f:
		for item in res:
			f.write(str(item) + '\n\n')



def responsiblePersonIds():
	"""
	Sends API requests using the requests module 
	This lists all the webscan templates + ids
	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/users"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	for url in url_api:
		r = requests.get(url, headers=headers)
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] Fetching all available responsible Persons Ids")
			rs = r.text
			res = json.loads(rs)
	print ("[-] Writing into file ./info/responsiblePersonIds.txt\n")
	with open('./info/responsiblePersonIds.txt', 'w') as f:
		for item in res:
			f.write(str(item) + '\n\n')


discoveryScanIds();
discoveryScanNodeIds();
systemScanNodeIds();
webScanNodeIds();
systemScanTemplateIds();
webScanTemplateIds();
responsiblePersonIds();

print ("[!] You can use grep to make life easy e.g: $grep -rnw ./ -e '<searchword>'\n")
