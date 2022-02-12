#!/usr/bin/env python3

import requests
import json
import csv
import nmap

#CPE = input("Please enter CPE(s):\n")
#print(type(CPE))


#Victoria's Code
#=============================================
'''#Final output list of string CPEs
inputFinal = []

#Users select from menu
TypeofInput = input ("""\nPlease select from the following: 1) To enter CPE value 2) To load file with CPE values  3) To run an nmap scan \nEnter number:  """)


#1) Manual Input of CPEs
if TypeofInput == "1":
    #String input of CPEs
    CPEsString = input("Enter CPE(s) separated by a comma \",\" :\n")
    #Number of CPEs entered
    if len(CPEsString) > 0:
        NumofCPEs = CPEsString.count(",") + 1
        #One CPE
        if NumofCPEs == 1:
            inputFinal.append(CPEsString)
        #More than one CPE
        elif NumofCPEs > 1:
            if ", " in CPEsString:
                inputFinal = CPEsString.split(", ")
            else:
                print("thisoneworks")
                inputFinal = CPEsString.split(",")
    else:
        print("Input invalid") #this line needs trouble shooting TODO

    #Test of input#1
    print(inputFinal)

#file with list of CPEs
if TypeofInput == "2":

    with open('readmetest.txt') as f:
        lines = f.readlines()
        for item in lines:
            inputFinal.append(item.strip())

    print(inputFinal)


#NMap scan
if TypeofInput == "3":
    scanner = nmap.PortScanner()
    ipInput = input("Enter IP address:") #input should not be a string
    print("Nmap Test")
    print("You entered " + ipInput)

    #Scan Type
    TypeofScan = input("""\nPlease enter the type of scan from the following: 1) OS 2) Services \nEnter input:  """)
    if TypeofScan == "1":
        #nmap, ipaddress, port, type of scan
        scanner.scan(ipInput, '-sV') #TODO
        print(scanner.scaninfo())
        print("a if 1 works")
    if TypeofScan == "2":
        print("b if 2 works")


#TODO: Determine input validation'''


#End of Vitoria's Code
#==============================================

'''
# Tony L's code
# ==========================
##response = requests.get("https://vuln.sentnl.io/api/cvefor/" + CPE)
response = requests.get("https://vuln.sentnl.io/api/cvefor/cpe:/a:apache:activemq_artemis:2.6.3")
#cpe:/a:apache:activemq_artemis:2.6.3

#print(type(response))
data = response.json()
#print(data)
#print("-" * 40 + "\n")
#print(type(data))
#print(len(data))
#print(data[1])
# ====================================
'''

'''
#DANIEL====================================================================================

d = {}
d3 = {}
my_list = []
cpe_range = len(data)
index = 0
CPE = "cpe:2.3:a:apache:http_server:2.4.12:*:*:*:*:*:*:*"

#print(type(counter))
#print(counter)

for i in range(cpe_range):
    d["id"] = data[index]["id"]
    d["cvss"] = int(data[index]["cvss"])
    #d["summary"] = data[index]["summary"]
    #d["references"] = data[index]["references"]
    
    d = d.copy()
    my_list.append(d)
    d.clear()

    #d2["CVE" + "_" + str(index)] = dict(d)

    #d2 = dict(reversed(sorted(d2.items(), key=lambda item: (item[1]["cvss"]))))
    index += 1
  
d3[CPE] = my_list
d3[CPE].pop()
print(d3)
'''

#Tony P.
#============================================================

###validated input
list_CPE = [
  'cpe:/a:apache:activemq_artemis:2.6.3','cpe:2.3:a:apache:http_server:2.4.12:*:*:*:*:*:*:*',
  'cpe:2.3:a:apache:accumulo:1.7.0:*:*:*:*:*:*:*']

###for loop to add each CPE as key to dict_CPE, list_CVE (server response) as value, dict_CVE_attributes ('id', 'CVSS' etc.) as sub-dictionaries
dict_mock_data = {}
for i in range(len(list_CPE)):
  response = requests.get("https://vuln.sentnl.io/api/cvefor/" + list_CPE[i])
#  print(response)
  data = response.json()

###mock server response (list of dictionaries by CVE)
#  list_mock_response_per_CPE = [ #list_dict_CVE pfor each CPE
#  {'id':'CVE_1','CVSS':5.1,'summary':'blah','reference':'mah'},
#  {'id':'CVE_2','CVSS':3.2,'summary':'bleh','reference':'meh'},
#  {'id':'CVE_3','CVSS':4.3,'summary':'blih','reference':'mih'}]
#  print(list_CPE[i])
#  print(response_server[i])

  dict_mock_data[list_CPE[i]] = data #or use mock server response
#print(dict_mock_data)

###mock CPE:CVE dictionary
#dict_mock_data = {
#  'CPE_1':[
#  {'id':'CVE_1','CVSS':5.1,'summary':'blah','reference':'mah'},
#  {'id':'CVE_2','CVSS':3.2,'summary':'bleh','reference':'meh'},
#  {'id':'CVE_3','CVSS':4.3,'summary':'blih','reference':'mih'}],
#  'CPE_2':[
#  {'id':'CVE_4','CVSS':3.4,'summary':'bloh','reference':'moh'},
#  {'id':'CVE_5','CVSS':5.5,'summary':'bluh','reference':'muh'}]
#  }
#print(dict_mock_data)
#print(len(dict_mock_data))
#print(dict_mock_data.items())

#####list_CVSS = [] #list of CVSS_sorted

###CSV writer_header
header = ["CPE","CVE","CVSS","Summary","References"]
with open('CVE_output.csv', 'w', encoding='UTF8') as f:
  writer = csv.writer(f)
  writer.writerow(header)

###iterate through CPE:CVE_list dictionary ("CPE_input":"server_response_list")
for key_CPE in dict_mock_data:
  print(key_CPE + "\n")

###sort list of dictionaries (key_CPE:value) by CVSS:value
  dict_mock_data_sorted = sorted(dict_mock_data[key_CPE], key=lambda x: x['cvss'], reverse=True) 
#  print(dict_mock_data_sorted)

###iterate through list_dict_CVE per CPE
  for dict_CVE in dict_mock_data_sorted:
#    print(dict_CVE)
    print("| " + str(dict_CVE['id']) + " ", end="") ###hard-format
    print("| CVSS: " + str(dict_CVE['cvss']) + " |\n")
    print("| Summary | " + str(dict_CVE['summary']) + "\n")
#    print("| References | " + str(dict_CVE['references']) + "\n")
#out_2    print("\n")

###CSV writer_data
    data = [
      key_CPE,str(dict_CVE['id']),
      str(dict_CVE['cvss']),
      str(dict_CVE['summary']),
      str(dict_CVE['references'])
      ]
#    print(data)
    with open('CVE_output.csv', 'a', encoding='UTF8') as f:
      writer = csv.writer(f)
      writer.writerow(data)

#####    list_CVSS.append(dict_CVE['CVSS'])
#####    print(list_CVSS)

#out_2    for key_CVE in dict_CVE: #iterate through dict_CVE ##loop-format
#out_2      print(key_CVE + " = " + str(dict_CVE[key_CVE]))

  print("-"*66)

#Tony P.
#============================================================

'''
#print("-" * 40 + "\n")
#print("DICTIONARY KEYS ARE:")
#print(data.keys())

CVE_list = [data_list['id'] for data_list in data]
CVE = '\n'.join(CVE_list)

CVSS_list = [data_list['cvss'] for data_list in data]

CVSS = '\n'.join(map(str,CVSS_list))

summary_list = [data_list['summary'] for data_list in data]
summary = '\n'.join(summary_list)

link_list = [data_list['references'] for data_list in data]
#print(link_list)
link_list2 = link_list[0]
#print(link_list2)
ext_link = '\n'.join(link_list2)

# get the "misc" key to get a link to remediation

print("CVE: " + CVE + "\n" +
"CVSS: " + str(CVSS) + "\n\n" +
"Summary: " + summary + "\n\n" + 
"External Link(s):\n" + ext_link)


#!/usr/bin/env python3

import requests

query = {"id":"pe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*"}
response = requests.get("https://vuln.sentnl.io/api/cve/CVE-2016-3333",params = query)
data = response.json()

print(data)
print("-" * 40 + "\n")
print(type(data))
print("-" * 40 + "\n")
print("DICTIONARY KEYS ARE:")
print(data.keys())
'''