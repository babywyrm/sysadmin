#!/usr/bin/python3

##
##
## https://ismaileltahawy.com/?p=434
############################################
############################################
##

import requests
import sys
from xmltodict import parse,OrderedDict
from pprint import pprint
import xml.etree.ElementTree as ET

ses = requests.Session()
ses.headers.update({"X-Requested-With":"DD automation platform - Development"})
auth_values = ('username','password')

'''
#Building asset dictionary (AssetID:name)
id = i["id"]
name = i["name"]
asset_dict[id]=name
asset_dict = build_asset_ID(url8)
pprint(asset_dict)
j="demo12.s02.sjc01.qualys.com"
print(asset_dict["26088034"])
for id, name in asset_dict.items():
    if name == j:
        print(id)
'''

def fetch_asset_details(url):
    try:
        resp = ses.post(url, auth=auth_values)
        data=parse(resp.text)
        y=1
        j = data["ServiceResponse"]["data"]["HostAsset"]
        for i in j:
            print("Host number : ",y)
            print("     Asset ID is : "+i["id"])
            print("     Asset Name is : "+i["name"])
            print("     Asset IP address : "+i["address"])
            print("     Asset tracking method : "+i["trackingMethod"])
            print("     Asset Creation date : "+i["created"])
            print("     Asset Last modified : "+i["modified"])
            print("     Asset Type : "+i["type"])
            print("     Asset tags : ")
            for j in i["tags"]["list"]["TagSimple"]:
                print("             "+j["name"])
            print("     Host ID : "+i["qwebHostId"])
            print("     Last Compiance Scan : "+i["lastComplianceScan"])
            print("     Last Vuln Scan : "+i["lastVulnScan"])
            print("     Asset OS : "+i["os"])
            try:
                print("     Asset dnsHostName : "+i["dnsHostName"])
            except KeyError:
                pass
            try:
                print("     Asset netbiosName : "+i["netbiosName"])
            except KeyError:
                pass
            y +=1
            print("--------------------------------------------------")

    except Exception as e:
        print("Error is : ",e)

def fetch(url):
    try:
        resp = ses.get(url, auth=auth_values)
        data=parse(resp.text)
        j=1
        for i in data["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]:
            print("Scan number ",j)
            print(" Scan Reference is : ",i["REF"])
            print(" Scan TYPE is : ",i["TYPE"])
            print(" Scan TITLE is : ",i["TITLE"])
            print(" User generated the scan is : ",i["USER_LOGIN"])
            print(" Scan LAUNCH DATE and TIME is : ",i["LAUNCH_DATETIME"])
            print(" Scan DURATION is : ",i["DURATION"])
            print(" Scan PRIORITY is : ",i["PROCESSING_PRIORITY"])
            print(" Scan STATUS is : ",i["STATUS"])
            print(" Scan TARGET is : ",i["TARGET"])
            print("-------------------------------------")
            j +=1
    except Exception as e:
        print("Error is : ",e)

def fetch_by_TAG_name(url):
    try:
        tag_name=input("Please enter the TAG name...")
        url2=url+tag_name
        resp = ses.get(url2, auth=auth_values)
        data=parse(resp.text)
        print("Hosts under TAG "+tag_name+" is : ")
        for i in data["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"]:
            print("Host ID: ",i["ID"])
            print("Asset IP: ",i["IP"])
            print("Asset DNS: ",i["DNS"])
            print("Asset OS: ",i["OS"])
            print("-----------------------")
    except Exception as e:
        print("Error is : ",e)

def add(url):
    try:
        ip_add=input("Please enter the IP you want to add..")
        add_payload = {"action":"add","ips":ip_add,"enable_vm":"1","enable_pc":"1"}
        resp = ses.post(url, data=add_payload, auth=auth_values)
        data=parse(resp.text)
        print("Result of action is : "+data["SIMPLE_RETURN"]["RESPONSE"]["TEXT"])
    except Exception as e:
        print("Error is : ",e)

def scan(url):
    try:
        ip_addr=input("Please enter the IP you want to scan (note: it must be added before in Assets)...")
        scan_title=input("Please enter the title of this scan...")
        status=input("Activate this schedule or note ? press ")
        payload = {"action":"launch","ip":ip_addr,"scan_title":scan_title,"option_title":"Initial Options"}
        resp = ses.post(url, data=payload, auth=auth_values)
        data=parse(resp.text)
        print("Result : "+data["SIMPLE_RETURN"]["RESPONSE"]["TEXT"])
        print("Scan Reference is : "+data["SIMPLE_RETURN"]["RESPONSE"]["ITEM_LIST"]["ITEM"][1]["VALUE"])
    except Exception as e:
        print("Error is : ",e)

def scan_per_tag(url):
    try:
        scan_title=input("Please enter the title of this scan : ")
        tag=input("Please enter the TAG name that you want to scan its assets : ")
        payload = {"action":"launch","target_from":"tags","tag_set_by":"name","tag_set_include":tag,"scan_title":scan_title,"option_title":"Initial PC Options"}
        resp = ses.post(url, data=payload, auth=auth_values)
        data=parse(resp.text)
        print("Result : "+data["SIMPLE_RETURN"]["RESPONSE"]["TEXT"])
        print("Scan Reference is : "+data["SIMPLE_RETURN"]["RESPONSE"]["ITEM_LIST"]["ITEM"][1]["VALUE"])
        print("---------------------------")
    except Exception as e:
        print("Error is : ",e)

def tag_get_info(url):
    try:
        resp = ses.post(url, auth=auth_values)
        data=parse(resp.text)

        for i in data["ServiceResponse"]["data"]["Tag"]:
            print("Tag name is : ",i["name"])
            print("Tag ID is : ",i["id"])
            print("--------------------------")
    except Exception as e:
        print("Error is : ",e)

def group_list(url):
    try:
        resp = ses.get(url, auth=auth_values)
        data=parse(resp.text)
        for i in data["ASSET_GROUP_LIST_OUTPUT"]["RESPONSE"]["ASSET_GROUP_LIST"]["ASSET_GROUP"]:
            #print(i)
            print("Group ID is: ",i["ID"])
            print("Group name is: ",i["TITLE"])
            for j in i["IP_SET"]:
                if j == "IP":
                    print("Asset IP is : ",i["IP_SET"]["IP"])
                elif j == "IP_RANGE":
                    print("Asset range is : ",i["IP_SET"]["IP_RANGE"])
            print("-----------------------")
    except Exception as e:
        print("Error is : ",e)

def group_edit(url):
    try:
        ip_addr=input("Please enter the asset IP address : ")
        group_name='servers'
        group_id=input("Please enter the group ID : ")
        payload={"id":group_id ,"add_ips":ip_addr}

        resp = ses.post(url, data=payload, auth=auth_values)
        data=parse(resp.text)
        print("The action result is : "+data["SIMPLE_RETURN"]["RESPONSE"]["TEXT"])
    except Exception as e:
        print("Error is : ",e)

def get_asset_info(url):
    try:
        asset_ID=input("Please enter Asset ID:")
        url2=url+asset_ID
        resp = ses.get(url2, auth=auth_values) #get the asset details using ID
        data=parse(resp.text)
        #pprint(data)
        print("Asset ID: " +data["ServiceResponse"]["data"]["HostAsset"]["id"])
        print("Asset name: " +data["ServiceResponse"]["data"]["HostAsset"]["name"])
        print("Asset address: " +data["ServiceResponse"]["data"]["HostAsset"]["address"])
        print("Tags for this client are: ")
        for i in data["ServiceResponse"]["data"]["HostAsset"]["tags"]["list"]["TagSimple"]:
            print("  "+i["name"])
    except Exception as e:
        print("Error is : ",e)

def tag_update(url):
    try:
        tag_id=input("Please enter the TAG ID : ")
        xml = """<?xml version="1.0" encoding="UTF-8" ?>
    <ServiceRequest>
        <data>
        <HostAsset>
        <tags>
          <add>
         <TagSimple><id>"""+tag_id+"""</id></TagSimple>
       </add>
          </tags>
          </HostAsset>
        </data>
    </ServiceRequest>"""
        asset_id=input("Please enter the asset ID : ")
        url2=url+asset_id
        resp = ses.post(url2, auth=auth_values, data=xml) #to update the asset
        data=parse(resp.text)
        print("Result is : "+data["ServiceResponse"]["responseCode"])
    except Exception as e:
        print("Error is : ",e)

def compliance_scan_list(url):
    try:
        resp = ses.get(url, auth=auth_values)
        data=parse(resp.text)
        for i in data["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]:
            if i != 'ID':
                print("Scan ID : "+i["ID"])
                print("Scan Ref : "+i["REF"])
                print("Scan Type : "+i["TYPE"])
                print("Scan Title : "+i["TITLE"])
                print("Scan done by User : "+i["USER_LOGIN"])
                print("Scan Launch date : "+i["LAUNCH_DATETIME"])
                print("Scan Duration : "+i["DURATION"])
                print("Scan Targets : "+i["TARGET"])
                print("----------------------------------------")
            else:
                print("Scan ID : "+data["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]["ID"])
                print("Scan Ref : "+data["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]["REF"])
                print("Scan Type : "+data["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]["TYPE"])
                print("Scan Title : "+data["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]["TITLE"])
                print("Scan done by User : "+data["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]["USER_LOGIN"])
                print("Scan Launch date : "+data["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]["LAUNCH_DATETIME"])
                print("Scan Duration : "+data["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]["DURATION"])
                print("Scan Targets : "+data["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]["TARGET"])
                print("----------------------------------------")
    except Exception as e:
        print("Error is : ",e)

def compliance_scan_launch(url1):
    try:
        ip_addr=input("please enter IP you want to launch compliance scan on : ")
        title=input("please enter the title compliance scan on : ")
        url2=f"?action=launch&ip={ip_addr}&scan_title={title}&option_title=Initial PC Options"
        url=url1+url2
        resp = ses.post(url, auth=auth_values)
        data=parse(resp.text)
        print("Result of action : "+data["SIMPLE_RETURN"]["RESPONSE"]["TEXT"])
    except Exception as e:
        print("Error is : ",e)

def scheduled_vuln_scan_list(url):
    try:
        resp = ses.get(url, auth=auth_values)
        raw = resp.text

        root = ET.fromstring(raw)
        elements = root.findall("./RESPONSE/SCHEDULE_SCAN_LIST/SCAN")
        elements_count = len(elements)
        data=parse(raw)
        if elements_count > 1:
            print("Number of schedules is : ",elements_count)
            for i in data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]:
                 print("\tScan ID is : "+i["ID"])
                 if i["ACTIVE"] == 1:
                     print("    Status : this scheduled scan is Active")
                 elif i["ACTIVE"] == 0:
                     print("\tStatus : this scheduled scan is Disabled")
                 print("\tScan Title is : "+i["TITLE"])
                 print("\tUser created the scan : "+i["USER_LOGIN"])
                 print("\tTargets of this scan : "+i["TARGET"])
                 print("\tScanner name : "+i["ISCANNER_NAME"])
                 print("\tOption profile used is : "+i["OPTION_PROFILE"]["TITLE"])
                 #print("Schedule every (in days): "+i["SCHEDULE"]["DAILY"]["@frequency_days"])
                 print("\tStart date : "+i["SCHEDULE"]["START_DATE_UTC"])
                 print("\tStart hour : "+i["SCHEDULE"]["START_HOUR"])
                 print("\tStart minute : "+i["SCHEDULE"]["START_MINUTE"])
                 print("-----------------------------------------------")
        elif elements_count == 1:
            print("Number of schedules is only ",elements_count)
            print("\tScan ID is : "+data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["ID"])
            if data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["ACTIVE"] == 1:
             print("\tStatus : this scheduled scan is Active")
            elif data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["ACTIVE"] == 0:
             print("\tStatus : this scheduled scan is Disabled")
            print("\tScan Title is : "+data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["TITLE"])
            print("\tUser created the scan : "+data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["USER_LOGIN"])
            print("\tTargets of this scan : "+data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["TARGET"])
            print("\tScanner name : "+data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["ISCANNER_NAME"])
            print("\tOption profile used is : "+data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["OPTION_PROFILE"]["TITLE"])
            #print("Schedule every (in days): "+i["SCHEDULE"]["DAILY"]["@frequency_days"])
            print("\tStart date : "+data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["SCHEDULE"]["START_DATE_UTC"])
            print("\tStart hour : "+data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["SCHEDULE"]["START_HOUR"])
            print("\tStart minute : "+data["SCHEDULE_SCAN_LIST_OUTPUT"]["RESPONSE"]["SCHEDULE_SCAN_LIST"]["SCAN"]["SCHEDULE"]["START_MINUTE"])
            print("-----------------------------------------------------")

    except Exception as e:
        print("Error is : ",e)

def scheduled_vuln_scan_create():
    try:

        #ip_addr=input("Please enter the IP you want to scan (note: it must be added before in Assets)...")
        #scan_title=input("Please enter the title of this scan...")
        ip_addr=input("Enter the IP address of the host: ")
        scan_title=input("Enter the title of that scan: ")
        time_zone_code="AU-VIC"
        option_title="Initial Options"
        active_status_ask=input("Do you want this schedule scan active ? enter 'y' and 'n' : ")
        if active_status_ask == "y":
            active_status=1
        elif active_status_ask == "n":
            active_status=0
        else:
            print("Wrong input ")
            sys.exit()

        occurrence_ask=input("please enter the occurrence, 'm' for monthly, 'w' for weekly and 'd' for daily : ")
        if occurrence_ask == "m":
            occurrence="monthly"
            recurrence=input("please enter recurrence value : ")
            start_hour=input("please enter the start hour (0-23) : ")
            start_minute=input("please enter the start minute (0-59) : ")
            frequency_months=input("please enter frequency months (1-12) : ")
            day_of_month=input("please enter day of month (1-31) : ")
            url_month=f"https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/schedule/scan/?action=create&scan_title={scan_title}&option_title={option_title}&active={active_status}&occurrence={occurrence}&start_hour={start_hour}&start_minute={start_minute}&time_zone_code={time_zone_code}&ip={ip_addr}&frequency_months={frequency_months}&day_of_month={day_of_month}&recurrence={recurrence}"
            print(url_month)
            resp = ses.post(url_month, auth=auth_values)
            data=parse(resp.text)
            print("Result : "+data["SIMPLE_RETURN"]["RESPONSE"]["TEXT"])
            print("Scan Reference is : "+data["SIMPLE_RETURN"]["RESPONSE"]["ITEM_LIST"]["ITEM"]["VALUE"])


        elif occurrence_ask == "w":
            occurrence="weekly"
            recurrence=input("please enter recurrence value : ")
            start_hour=input("please enter the start hour (0-23) : ")
            start_minute=input("please enter the start minute (0-59) : ")
            weekdays=input("please enter weekday (Sunday,.... Friday) : ")
            frequency_weeks=1
            url_week=f"https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/schedule/scan/?action=create&scan_title={scan_title}&option_title={option_title}&active={active_status}&occurrence={occurrence}&start_hour={start_hour}&start_minute={start_minute}&time_zone_code={time_zone_code}&ip={ip_addr}&weekdays={weekdays}&frequency_weeks={frequency_weeks}&recurrence={recurrence}"
            print(url_week)
            resp = ses.post(url_week, auth=auth_values)
            data=parse(resp.text)
            print("Result : "+data["SIMPLE_RETURN"]["RESPONSE"]["TEXT"])
            print("Scan Reference is : "+data["SIMPLE_RETURN"]["RESPONSE"]["ITEM_LIST"]["ITEM"]["VALUE"])

        elif occurrence_ask == "d":
            occurrence="daily"
            recurrence=input("please enter recurrence value : ")
            start_hour=input("please enter the start hour (0-23) : ")
            start_minute=input("please enter the start minute (0-59) : ")
            frequency_days=input("please enter frequency months (1-365) : ")
            url_days=f"https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/schedule/scan/?action=create&scan_title={scan_title}&option_title={option_title}&active={active_status}&occurrence={occurrence}&start_hour={start_hour}&start_minute={start_minute}&time_zone_code={time_zone_code}&ip={ip_addr}&frequency_days={frequency_days}&recurrence={recurrence}"
            print(url_days)
            resp = ses.post(url_days, auth=auth_values)
            data=parse(resp.text)
            print("Result : "+data["SIMPLE_RETURN"]["RESPONSE"]["TEXT"])
            print("Scan Reference is : "+data["SIMPLE_RETURN"]["RESPONSE"]["ITEM_LIST"]["ITEM"]["VALUE"])

        else:
            print("Wrong input ")
            sys.exit()

    except Exception as e:
        print("Error is : ",e)

def print_menu():
    print('What would you like to do : ')
    print("# Hosts:")
    print("   Press 2 to List all hosts and it's details: IP, ID OS..etc")
    print('   Press 12 to view details for a specific asset, i.e:name, IP, DNS, ID')
    print('   Press 3 to Add new host(s)/range/network')
    print("# Scans:")
    print("   Press 1 to List the previous Vul scans")
    print('   Press 4 to Launch immediate a new Vul scan per IP')
    print('   Press 8 to Launch a new Vul scan per a specific TAG')
    print("   Press 14 to List the previous Compliance scans")
    print("   Press 15 to Launch a new Compliance scans")
    print("   Press 16 to List all the Scheduled Vuln. scans")
    print("   Press 17 to launch a Scheduled Vuln. scan")
    print("# Tags:")
    print('   Press 6 to get the list of ALL TAGs and its IDs')
    print('   Press 18 to List all hosts TAGed by a specific TAG ')
    print('   Press 13 to update the asset TAG')
    print("# Groups")
    print('   Press 9 to list asset Groups')
    print('   Press 10 to add new asset in an existing Group')
    print('Press any other key to Exit \n')

    x = input()
    return(x)


def main():

    url2=f"https://qualysapi.qg3.apps.qualys.com/qps/rest/2.0/search/am/hostasset"
    url1="https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/scan/?action=list"
    url3="https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/asset/ip/"
    url4="https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/scan/"
    url6="https://qualysapi.qg3.apps.qualys.com/qps/rest/2.0/search/am/tag"
    url8="https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/scan/compliance/"
    url9="https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/asset/group/?action=list"
    url10=f"https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/asset/group/?action=edit"
    url18=f"https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/asset/host/?action=list&use_tags=1&tag_set_by=name&tag_set_include="
    url12=f"https://qualysapi.qg3.apps.qualys.com/qps/rest/2.0/get/am/hostasset/"
    url13="https://qualysapi.qg3.apps.qualys.com/qps/rest/2.0/update/am/hostasset/"
    url14="https://qualysapi.qg3.apps.qualys.com//api/2.0/fo/scan/compliance/?action=list"
    url15=f"https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/scan/compliance/"
    url16="https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/schedule/scan/?action=list"

    while True:
        choice = print_menu()
        if choice == "1":
            fetch(url1)

        elif choice == "2":
            fetch_asset_details(url2)

        elif choice == "3":
            add(url3)

        elif choice == "4":
            scan(url4)

        elif choice == "6":
            tag_get_info(url6)

        elif choice == "18":
            fetch_by_TAG_name(url18)

        elif choice == "8":
            scan_per_tag(url8)

        elif choice == "9":
            group_list(url9)

        elif choice == "10":
            group_edit(url10)

        elif choice == "12":
            get_asset_info(url12)

        elif choice == "13":
            tag_update(url13)

        elif choice == "14":
            compliance_scan_list(url14)

        elif choice == "15":
            compliance_scan_launch(url15)

        elif choice == "16":
            scheduled_vuln_scan_list(url16)

        elif choice == "17":
            scheduled_vuln_scan_create()

        else:
            print("Closing the script..bye!")
            sys.exit()

if __name__ == "__main__":
    main()
    
##############################
##
