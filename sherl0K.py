#!/usr/bin/env python3
"""
				--- by Yuri BlackTie ----
 	The sherl0K.py will add discovery scans to a vulnerability scan group as asset update sources 
 			Shout out @Connor for the splitting_range code 
 				
"""
import ipaddress
import math
import argparse
import csv
import requests
import simplejson as json
import json
import ast
from time import sleep

"""
Argparse was used to get user input that will be used to:
 * split the subnet into smaller subnets
 * label the scan name 
 * include the exclusion subnets/hosts/ranges
 
 Example: ./hostScan.py --ip_cidr=192.168.0.0/24 --target_suffix=25 --exclusions 192.168.0.1-100

"""

parser = argparse.ArgumentParser()
parser.add_argument("-o", "--output_file_name", help="Name of resulting csv file")
parser.add_argument("-i", "--ip_cidr", default=None, type = str, help="The larger subnet to split")
parser.add_argument("-t", "--target_suffix", default=20, type = int, help="The smaller subnets to split into")
parser.add_argument("-n", "--scan_name", default='Script-scan', type = str, help="Name of scan, csv input")
parser.add_argument("-e", "--exclusions", default='', type = str, help="The ips to exclude")

args = parser.parse_args()


def get_ip_counts(ip_range: str) -> dict:
    prefix = int(ip_range.split("/")[1])
    return {"hosts": 2**(32-prefix), "networks": 2**(prefix)}


def gen_range(ip_range: str) -> list:
    return list(map(lambda x: str(x),ipaddress.ip_network(ip_range)))


def get_host_count(prefix: int) -> int:
    return 2**(32-prefix)


def split_range(ip_cidr=args.ip_cidr, target_suffix=args.target_suffix) -> list:
    """
        Splits the ip range into multiple smaller blocks of size /target_suffix
        Returns an array with the seperate blocks in cidr notation
    """

    source_ip = ip_cidr.split('/')[0] 
    source_prefix = int(ip_cidr.split('/')[1])

    source_hosts = get_host_count(source_prefix)
    target_hosts = get_host_count(target_suffix)

    blocks_required = math.ceil(source_hosts/target_hosts)
    ip = source_ip
    results: list = [f"{ip}/{target_suffix}"]
    for i in range(blocks_required-1):
        new_ips = gen_range(f"{ip}/{target_suffix}")
        ip = str(ipaddress.IPv4Address(new_ips[len(new_ips)-1])+1)
        results.append(f"{ip}/{target_suffix}")
    return results


def expand_blocks(ip_ranges: list):
    """
    Takes in an array of CDIR ip ranges and generates the entire range.
    Useful for testing by saying:
    	gen_range("large_ip_range") == expand_blocks(split_range("large_ip_range", 20))
    """
    results = []
    for ip_range in ip_ranges:
        results.extend(gen_range(ip_range))
    return results


split_range = f'{",".join(split_range(ip_cidr=args.ip_cidr, target_suffix=args.target_suffix))}'
#print(split_range(ip_cidr=args.ip_cidr, target_suffix=args.target_suffix))
#print(expand_blocks(split_range(ip_cidr=args.ip_cidr, target_suffix=args.target_suffix)))


def generate_csv(split_range: str, scan_name=args.scan_name, exclusions=args.exclusions):
	"""
	Takes in an array of CDIR ip ranges and user supplied exclusions and scan name
	Generates a csv that the Radar can consume
	"""
	with open('target.csv', 'w') as fd:
		  fd.write(f'"{split_range}","{args.scan_name}","{args.exclusions}"')
	print ('[*] A csv file "targets.csv" created')


a"""
Out-of-the-box the script will prompt user input from the command prompt and display the input (first two
lines). 

You can to hard code (on the third line) your values using data gathered from running the orakl.py script. 

I would leave the discoveryScan Id prompt as is, as this allows the script to capture you input as a list
which is later used to build the request payload. 
"""

aak=input('[?] Enter ApiAccessKey : ')
print(aak)
#accesskey = " "  

ask=input('[?] Enter ApiSecretKey : ')
print(ask)
#secretkey = " "

email=input('[?] Enter Email Address : ')
print(email)
#email = 'a@b.com'

scanGroupName=input('[?] Enter Vulnerability scanGroupName : ')
print(scanGroupName)
#scanGroupName = " "

responsiblePersonId=input('[?] Enter your responsiblePersonId : ')
print(responsiblePersonId)
#responsiblePersonId = ' '

systemScanTemplateId=input('[?] Enter the systemScanTemplateId : ')
print(email)
#systemScanTemplateId = ' '

systemScanNodeId=input('[?] Enter the systemScanNodeId : ')
print(systemScanNodeId)
#systemScanNodeId = ' '

webScanTemplateId=input('[?] Enter your webScanTemplateId : ')
print(webScanTemplateId)
#webScanTemplateId = ' '

webScanNodeId=input('[?] Enter your webScanNodeId : ')
print(webScanNodeId)
#webScanNodeId = ' '



def api_auth():
	"""
	Sends API requests using the requests module 
	This checks the validity of the authentication API access and secret keys

	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/account/details"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	#headers['ApiAccessKey'] = accesskey
	#headers['ApiSecretKey'] = secretkey
	#serialized= json.dumps(headers).encode("utf-8")
	#print(headers)

	for url in url_api:
		r = requests.get(url, headers=headers)
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] Authentication was successful\n")
			print (r.text + '\n\n')
		#info = json.loads(r.decode("utf-8"))


def api_ldiscNodes():
	"""
	Sends API requests using the requests module 
	This checks the validity of the authentication API access and secret keys

	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/scannodes/discoveryScan"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	#headers['ApiAccessKey'] = accesskey
	#headers['ApiSecretKey'] = secretkey
	#serialized= json.dumps(headers).encode("utf-8")
	#print(headers)

	for url in url_api:
		s = '{"Name"'
		r = requests.get(url, headers=headers)
		print(r.status_code)
		if r.status_code == 200:
			print ("[*] The following are the available discovery nodes")
			rs = r.text
			res = json.loads(rs)
			#print ("node[0]", res[0])
			for i in res:
				print(i["Name"],i["Value"])
			#print (res)
		#info = json.loads(r.decode("utf-8"))


def api_addDiscScan(split_range: str, accesskey: str, secretkey: str, scan_name=args.scan_name, exclusions=args.exclusions):
	"""
	The API requests using the requests module 
	request will create a DiscoveryScan
	the user is prompted to enter some detail useful for this bit of info
	See the parameters and values defined herein in the README.txt file
	"""

	#email = input('Enter your email for notifications: ') #need to set this up nice later

	null = None
	url_api = {"https://api.radar.f-secure.com/api/integration/DiscoveryScans"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey} 
	payload =  {'CanStartScan': False,'Exclude': null,'Id': null,'LastReportId': null,'Name': null,'Range': null,'ReportId': null,'ResponsibleUser': null,'ScanLastCompleted': null,'ScanLastSeen': null,'ScanNode': {"Name":"General Purpose Discovery Scan","Id":"da771c58-10df-472c-9069-7fa8460d7b18"},"ScanNodeId":"da771c58-10df-472c-9069-7fa8460d7b18","ScanRunState":"Idle","ScanStatistics":null,"ScanTemplate":{"Name":"Host Discovery [T1]","Id":"3ce1292a-ea86-4840-b5b5-1efe7a5c01d0"},'ScheduleOption': {'SchedulingMode':'None'},'AssetMonitorings': null,'TemplateId': '3ce1292a-ea86-4840-b5b5-1efe7a5c01d0','scanTargets': [{'Range': '%s'%split_range ,'Name': '%s'%scan_name,'Exclude': '%s'%exclusions,'invalidRangeSize': True}],'scanMode': 'hostDiscovery','MessageNotification': [{'EmailAddresses': '%s'%email,'NotificationLevel': 'ScanStartsEnds','NotificationLevelId': '6'}]}

	for url in url_api:
		r = requests.post(url, headers=headers, data=json.dumps(payload))
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] A discovery scan added successfully")
			#print (r.text)
		ScanIds = r.text
		return ScanIds


def api_addVulnScanGrp(res: str):
	"""
	The API requests using the requests module 
	request will create a Vulnerability Group and add all of the discovery scans created as an “asset update source”. 
	See the parameters and values defined herein in the README.txt file
	"""

	discoveryScanId = res
	null = None
	url_api = {"https://api.radar.f-secure.com/api/integration/scangroups/"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey} 
	payload =  {'ScanningMode':'RegularScan','AssetMonitoringConfigurations':[{'Id': null,'TrackSystemScans':'true','IsActive': True,'AssetSourceType':'DiscoveryScan','DiscoveryScanId':'%s'%discoveryScanId,'ScheduleId': '','RemoveSystemScanWhenUndiscovered': False,'RunSystemScanImmediatelyAfterAdd': True,'RunSystemScanImmediatelyIfNewServicesDiscovered': True},{'Id':null,'TrackWebScans':'True','IsActive': True,'AssetSourceType':'DiscoveryScan','DiscoveryScanId':'%s'%discoveryScanId,'ScheduleId':'','RemoveWebScanWhenUndiscovered': False,'RunWebScanImmediatelyAfterAdd':True,'TrackedHttpPortRangeForWebScan':'80','TrackedHttpsPortRangeForWebScan':'443'}],'ScanGroupName':'%s'%scanGroupName,'ScanDescription':'A Script-created Vulnerability group','ResponsiblePersonId':'%s'%responsiblePersonId,'SystemScanSettingsEnabled': True,'ScanTargets':[],'MaxSystemScans':5,'SystemScanTemplateId':'%s'%systemScanTemplateId,'SystemScanNodeId':'%s'%systemScanNodeId,'SystemScanScheduleId': null,'WebScanSettingsEnabled':True,'MaxWebScans': 3,'WebScanTemplateId':'%s'%webScanTemplateId,'WebScanNodeId':'%s'%webScanNodeId,'WebScanScheduleId': null,'MessageNotification':[{'EmailAddresses':'','NotificationLevel':'Never','NotificationLevelId':'0'}]}
	for url in url_api:
		r = requests.post(url, headers=headers, data=json.dumps(payload))
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] A vulnerability scan group added successfully:")
			rx = r.text
			rex = json.loads(rx)
		groupScans = rex['AssignedToUser']
		return groupScans


def api_launchDiscScan(split_range: str, accesskey: str, secretkey: str):
	"""
	The API requests using the requests module 
	request will launch a DiscoveryScan created
	"""

	ScanIds = f'{api_addDiscScan(split_range, accesskey, secretkey)}'
	res = ScanIds.strip('"]["')
	print ('[*] The discovery scan Id is', res)
	assigned = f'{api_addVulnScanGrp(res)}'
	print (assigned)

	url_api = {"https://api.radar.f-secure.com/api/integration/discoveryscans/" +res+ "/start"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey} 

	for url in url_api:
		r = requests.put(url, headers=headers)
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] The discovery scan launched successfully")




generate_csv(split_range, scan_name=args.scan_name, exclusions=args.exclusions);
api_auth();
api_launchDiscScan(split_range, accesskey, secretkey);
#api_addVulnScanGrp();
#api_ldiscNodes();

