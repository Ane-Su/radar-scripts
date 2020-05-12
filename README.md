Project Overview 

F-Secure Radar is difficult to use when dealing with large IP ranges. The ranges need to be broken up into smaller subnets of /20 and /18. Additionally, these subnets then need to be manually added to a “Scan Group”. This can become very time consuming and makes using Radar difficult. To make this process easier a number of Python scripts will need to be made to perform these processes using the API and thus removing the manual effort required. 

This repo has three scripts which can be discribed as follows:

#script_one: sherl0K.py
- splits a user provided large ip range into smaller ip ranges of the user's choosing (/18,/20, /24.etc) 
- combines the smaller ranges with  user provided exclusion ip ranges and a scan name into a csv file that radar can consume
- uses this data to create a host discovery scan (you can tweak for port scanning) 
- creates a vulnerability scan group with user input
- launches the discovery scan

#script_two: 0rakl.py
- makes queries for information that a user would need to run the l0dt script
- writes the data into text files which can be grep'd for info

#script_three: l0dt.py
- prompts for user input with info that can be obtained by running script two
- allows a user to select a number of discovery scans that will be added as 'asset update sources' to a vulnerability group
- creates a vulnerability scan group with only system scan vulnerabilities and static variables (can be tweaked)
