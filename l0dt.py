#!/usr/bin/env python3
"""
				--- by Yuri BlackTie ----
 	The l0kt.py will add discovery scans to a vulnerability scan group as asset update sources 
 			
 				Example: ./l0kt.py
"""

import requests
import simplejson as json
import json
import ast

"""
Out-of-the-box the script will prompt user input from
the command prompt and display the input (first two
lines). 

You can to hard code (on the third line) your values 
using data gathered from running the orakl.py script. 

I would leave the discoveryScan Id prompt as is, as
this allows the script to capture you input as a list
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


"""
This part will get user input to build a list of discoveryScans that 
you want to add as asset resources to this vuln scan group
"""

lst = []  # creating an empty list 
n = int(input("Enter the number of Discovery Scans to add : ")) 	# number of elements as input 
for i in range(0, n): 	# iterating and till the range 
    ele = str(input())  
    lst.append(ele) 	# adding the element 
#print(lst) 


def api_auth():
	"""
	Sends API requests using the requests module.
	Checks the validity of the API's authentication access and secret keys.

	"""

	url_api = {"https://api.radar.f-secure.com/api/integration/account/details"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey}
	for url in url_api:
		r = requests.get(url, headers=headers)
		#print(r.status_code)
		if r.status_code == 200:
			print ("[*] Authentication was successful\n")
			print (r.text + '\n\n')
		#info = json.loads(r.decode("utf-8"))



def api_addVulnScanGrp():
	"""
	Sends API requests using the requests module.
	Creates a Vulnerability Scan Group and adds user specified discovery scans as an “asset update source”. 
	See the parameters and values defined herein in the README.txt file.
	"""

	null = None
	url_api = {"https://api.radar.f-secure.com/api/integration/scangroups/"}
	headers = {'Content-Type': 'application/json', 'ApiAccessKey': '%s'%accesskey  , 'ApiSecretKey': '%s'%secretkey} 
	payload =  {'ScanningMode':'RegularScan','AssetMonitoringConfigurations':[],'ScanGroupName':'%s'%scanGroupName,'ScanDescription':'A Script-created Vulnerability group','ResponsiblePersonId':'%s'%responsiblePersonId,'SystemScanSettingsEnabled': True,'ScanTargets':[],'MaxSystemScans':5,'SystemScanTemplateId':'%s'%systemScanTemplateId,'SystemScanNodeId':'%s'%systemScanNodeId,'SystemScanScheduleId': null,'WebScanSettingsEnabled':True,'MaxWebScans': 3,'WebScanTemplateId':'%s'%webScanTemplateId,'WebScanNodeId':'%s'%webScanNodeId,'WebScanScheduleId': null,'MessageNotification':[{'EmailAddresses':'','NotificationLevel':'Never','NotificationLevelId':'0'}]}
	for i in lst:
		res = {"Id":null,"TrackSystemScans":"True","IsActive":True,"AssetSourceType":"DiscoveryScan","DiscoveryScanId":"%s"%i,"ScheduleId":"556f1e21-34c5-4ae5-87f3-95c3be91b7e5","RemoveSystemScanWhenUndiscovered":False,"RunSystemScanImmediatelyAfterAdd":True,"RunSystemScanImmediatelyIfNewServicesDiscovered":True}
		payload["AssetMonitoringConfigurations"].append(res) # recursively adding the asset sources
	for url in url_api:
		r = requests.post(url, headers=headers, data=json.dumps(payload))
		if r.status_code == 200:
			print ("\n[*] A vulnerability scan group has been assigned to:")
			rx = r.text
			rex = json.loads(rx)
			print(rex['AssignedToUser'])
		groupScans = rex['AssignedToUser']
		return groupScans


api_auth();
api_addVulnScanGrp();


