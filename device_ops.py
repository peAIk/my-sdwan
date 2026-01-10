import argparse
import requests
import json
import yaml
import csv
from urllib.parse import urlparse
import subprocess
import pandas as pd
import os
from getpass import getpass
requests.packages.urllib3.disable_warnings()

class Authentication:

    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        url = base_url + api
        payload = {'j_username' : username, 'j_password' : password}

        response = requests.post(url=url, data=payload, verify=False)
        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")
            return(jsessionid[0])
        except:
            print("[ERROR] No valid JSESSION ID returned\n")
            exit()

    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        api = "/dataservice/client/token"
        url = base_url + api      
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return(response.text)
        else:
            return None

# Define the command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("csv", help="Exported CSV from 'UWAN parameters.xlsx'")

parser.add_argument("-n","--hostname", help="vManage hostname")
parser.add_argument("-u", "--username", help="Username", required=False)
parser.add_argument("-p", "--password", help="Password", required=False)

parser.add_argument("-g", "--confgroup", help="Configuration Group Id, if not provided, choose")
parser.add_argument("-m", "--mode", help="Mode 'associate/deploy/download/upload/tag/remove'",default='associate')
# parser.add_argument("-j", "--json", help="display in json format", action='store_true')
parser.add_argument("-t", "--tag", help="Associate tags to devices in file")
parser.add_argument("-v", "--verbose", help="Verbose level",action='count', default=0)
parser.add_argument("-i", "--include", help="Include devices seperated by comma")
parser.add_argument("-e", "--exclude", help="Exclude devices seperated by comma")
args = parser.parse_args()
dev_filter = args.include.split(",") if args.include else None
dev_filter_exlc = args.exclude.split(",") if args.exclude else None
csv_filename = args.csv
tag_id = args.tag
verbose = args.verbose


def print_error_message(response):
    return f"[ERROR] Failed to {args.mode.capitalize()}. Status Code: {response.status_code}:{response.reason}:{response.text}"

def print_verbose(message, verbose, verbose_level):
    if verbose >= verbose_level:
        print(message)
    else:
        return

def main():
    os.environ['NO_PROXY'] = 'cz.net.sys'
    # Define vManage information
    vmanage_host = args.hostname if args.hostname else 'vman.cz.net.sys'
    vmanage_port = '443'  # Default HTTPS port
    vmanage_username = args.username if args.username else input(f"{vmanage_host}\nUsername: ")
    vmanage_password = args.password if args.password else getpass("Password: ")
    bootstrap_directory = "./bootstrap"
    url_prefix = f'https://{vmanage_host}/dataservice'
    verbose_level = 0
    # import data from csv file
    try:
        csv_df = pd.read_csv(csv_filename)
        csv_data = csv_df.to_dict('records')
    except Exception as e:
        exit(f"[ERROR] File import failed.\n {e}")


    # csv_data = []
    # with open(csv_filename,"r") as csvfile:
    #     csv_reader = csv.DictReader(csvfile)
    #     for line in csv_reader:
    #         csv_data.append(line)

    for item in csv_data:
        item['device-id'] = item.pop('Device ID')
        item['host_name'] = item.pop('Host Name')
        item['site_id'] = item.pop('Site Id')
        item['system_ip'] = item.pop('System IP')
        item['ipv6_strict_control'] = item.pop('Dual Stack IPv6 Default')
        item['pseudo_commit_timer'] = item.pop('Rollback Timer (sec)')

    # print(json.dumps(csv_data, indent=2))
    if dev_filter:
        print(f"Device filter set. Devices included: {dev_filter}")

    if dev_filter_exlc:
        print(f"Device filter set. Devices excluded: {dev_filter_exlc}")
    # uprava pracne vygenerovaneho CSV a promennych do jine sestavy promennych pro API WTF #$%@
    sdwan_data = []
    for item in csv_data:
        new_item = {'device-id': item['device-id'], 'variables': []}
        for key, value in item.items():
            if key != 'device-id':
                new_item['variables'].append({'name': key, 'value' : value})
        # vynecha pokud je exluded nastaven a box nalezne v exluded filteru
        if dev_filter_exlc and item['host_name'] in dev_filter_exlc:
            print_verbose(f"[DEBUG] Skipping {item['host_name']}",verbose, 1)
            continue
        # prida, pokud je v included, pokud je included nastaven
        elif dev_filter and item['host_name'] in dev_filter:
            print_verbose(f"[DEBUG] Adding {item['host_name']}",verbose, 1)
            sdwan_data.append(new_item)
        # prida, pokud neni include nastaven a hostname existuje
        elif not dev_filter and item['host_name']:
            print_verbose(f"[DEBUG] Adding {item['host_name']}",verbose, 1)
            sdwan_data.append(new_item)



    total_devices = len(sdwan_data)
    print(f"Total devices to process: {total_devices}")
    # for item in sdwan_data:
    #     for var in item['variables']:
    #         var['value'] = int(var['value']) if var['value'].isdigit() else var['value']
    #         var['value'] = False if var['value'] == 'False' else True if var['value'] == 'True' else var['value']

    #print(json.dumps(sdwan_data, indent=2))

    try:
        Auth = Authentication()
        jsessionid = Auth.get_jsessionid(vmanage_host,vmanage_port,vmanage_username,vmanage_password)
        token = Auth.get_token(vmanage_host,vmanage_port,jsessionid)
    except Exception as e:
        exit(f"[ERROR] Connection to vManage failed with error:\n{e}")

    if token is not None:
        header = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
    else:
        header = {'Content-Type': "application/json",'Cookie': jsessionid}
    if token:
        print("[INFO] Login successful")
        confgroup_id = '' #'ccaf5680-7db5-4fca-b979-9ea2bebcfc60'
        if args.confgroup:
            confgroup_id = args.confgroup

        confgroup_id = confgroup_id.strip()

        if args.csv and args.mode == "remove":
            print("Current mode is REMOVE routers from config group")
            vmanage_url_req = f"/v1/config-group/{confgroup_id}"
            if not confgroup_id:
                vmanage_url_req = f"/v1/config-group"
                response = requests.delete(f"{url_prefix}{vmanage_url_req}",headers=header, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    print("List of existing configuration groups:")
                    for idx, item in enumerate(data):
                        print(f"[{idx}] Group ID: {item['id']}, Name: {item['name']}")
                else:
                    exit(print_error_message(response))

                while True:
                    selected_index = input(f"Select Configuration Group [0-{len(data)-1}]: ")
                    # confgroup_id = input("Insert Configuration Group ID: ")

                    # Validate and get the corresponding ID
                    try:
                        selected_index = int(selected_index)
                        selected_item = data[selected_index]
                        confgroup_id = selected_item['id']
                        confgroup_name = selected_item['name']
                        print(f"You selected: {selected_item['name']} (ID: {confgroup_id})")
                    except (ValueError, IndexError):
                        print("❌ Invalid selection. Please enter a valid number.")

                    if confgroup_id != "":
                        vmanage_url_req = f"{vmanage_url_req}/{confgroup_id}"
                        break
                    # print('No input!')

            vmanage_url_req = f"{vmanage_url_req}/device/associate"
            
            json_data = {"devices" : []}
            for item in sdwan_data:
                json_data["devices"].append({'id' : item['device-id']})
            print(f"URL: {url_prefix}{vmanage_url_req}")
            print("JSON data:")
            print(json.dumps(json_data, indent=2))
            
            while True:
                res = input(f"Press [enter] to DELETE routers with config grp {confgroup_id}:{confgroup_name} or [s] to SKIP...")
                if res == "":
                    response = requests.post(f"{url_prefix}{vmanage_url_req}",headers=header, json=json_data, verify=False)
                    if response.status_code == 200:
                        print("Association Successful")
                    else:
                        exit(print_error_message(response))
                    break
                elif res == "s":
                    break
                else:
                    continue
            
            if input("Do you want to ASSOCIATE routers? (y/n):") == "y":
                args.mode = "associate"

        if args.csv and args.mode == "associate":
            print("Current mode is ASSOCIATE routers to config group")
            vmanage_url_req = f"/v1/config-group/{confgroup_id}"
            if not confgroup_id:
                vmanage_url_req = f"/v1/config-group"
                response = requests.get(f"{url_prefix}{vmanage_url_req}",headers=header, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    print("List of existing configuration groups:")
                    for idx, item in enumerate(data):
                        print(f"[{idx}] Group ID: {item['id']}, Name: {item['name']}")
                else:
                    exit(print_error_message(response))

                while True:
                    selected_index = input(f"Select Configuration Group [0-{len(data)-1}]: ")
                    # confgroup_id = input("Insert Configuration Group ID: ")

                    # Validate and get the corresponding ID
                    try:
                        selected_index = int(selected_index)
                        selected_item = data[selected_index]
                        confgroup_id = selected_item['id']
                        print(f"You selected: {selected_item['name']} (ID: {confgroup_id})")
                    except (ValueError, IndexError):
                        print("❌ Invalid selection. Please enter a valid number.")

                    if confgroup_id != "":
                        vmanage_url_req = f"{vmanage_url_req}/{confgroup_id}"
                        break
                    # print('No input!')

            vmanage_url_req = f"{vmanage_url_req}/device/associate"
            
            json_data = {"devices" : []}
            for item in sdwan_data:
                json_data["devices"].append({'id' : item['device-id']})
            print(f"URL: {url_prefix}{vmanage_url_req}")
            print("JSON data:")
            print(json.dumps(json_data, indent=2))
            
            while True:
                res = input(f"Press [enter] to ASSOCIATE routers with config grp {confgroup_id} or [s] to SKIP...")
                if res == "":
                    response = requests.post(f"{url_prefix}{vmanage_url_req}",headers=header, json=json_data, verify=False)
                    if response.status_code == 200:
                        print("Association Successful")
                    else:
                        exit(print_error_message(response))
                    break
                elif res == "s":
                    break
                else:
                    continue


            if input("Do you want to DEPLOY routers? (y/n):") == "y":
                args.mode = "deploy"
        
        if args.csv and args.mode == "deploy":
            print("Current mode is DEPLOY configuration to routers")

            # get device variable set from configuration group
            if not confgroup_id:
                confgroup_id = input("Insert configuration group ID:")
            vmanage_url_req = f'/v1/config-group/{confgroup_id}/device/variables'
            
            # conf grp device variables JSON must be exaclty same as it is in concrete conf grp.
            response = requests.get(f"{url_prefix}{vmanage_url_req}",headers=header, verify=False)
            data = response.json()
            var_scheme = []
            for var in data['devices'][0]['variables']:
                var_scheme.append(var['name'])


            # conf group variable upload
            json_data = {'solution' : 'sdwan', 'devices' : []}
            # uprava pracne vygenerovaneho CSV a promennych do jine sestavy promennych pro API WTF #$%@
            for item in sdwan_data:
                item['variables'] = [d for d in item['variables'] if d['name'] in var_scheme]
                json_data['devices'].append(item)
            print("JSON data:")
            print(json.dumps(json_data, indent=2))
            print(f"URL: {url_prefix}{vmanage_url_req}")
            input("Check JSON and URL and press [enter] to upload variables into vmanage... (no return after this point )")

            response = requests.put(f"{url_prefix}{vmanage_url_req}",headers=header, json=json_data, verify=False)
            if response.status_code == 200:
                print("Variable upload is Successful")
            else:
                exit(print_error_message(response))


            # conf group deployment
            vmanage_url_req = f"/v1/config-group/{confgroup_id}/device/deploy"
            
            json_data = {"devices" : []}
            for item in sdwan_data:
                json_data['devices'].append({'id' : item['device-id']})
            print("JSON data:")
            print(json.dumps(json_data, indent=2))
            print(f"URL: {url_prefix}{vmanage_url_req}")

            input("Check JSON and URL and press [enter] to deploy routers in vmanage... (no return after this point )")
            
            response = requests.post(f"{url_prefix}{vmanage_url_req}",headers=header, json=json_data, verify=False)
            
            if response.status_code == 200:
                print("Deployment is successful")
            else:
                exit(print_error_message(response))

            # wait at least 30s and let finish deployment of routers before. Or downloaded configurations are not complete
            if input("Do you want to DOWNLOAD bootstrap (wait at least 30s after deploy and let finish deployment) configurations? (y/n):") == "y":
                args.mode = "download"


        if args.mode == "download":
            print("Current mode is DOWNLOAD bootstrap configuration from vManage")

            # bootstrap config
            vman_urls = []
            for item in sdwan_data:
                url = f"/system/device/bootstrap/device/{item['device-id']}?configtype=cloudinit&inclDefRootCert=true&version=v1"
                vman_urls.append({'device-id' : f"{item['device-id']}", 'url' : f"{url}"})
                # https://vman.cz.net.sys/dataservice/system/device/bootstrap/device/C8200-1N-4T-FGL2715MN4Q?configtype=cloudinit&inclDefRootCert=false&version=v1
            
                print(f"to download: {item['device-id']}")
            
            input("Check the URL (routers must have deployed configuration) and press [enter] to get bootstrap from vmanage... ")
            
            total_dl = len(vman_urls)
            success_dl = 0
            for item in vman_urls:
                response = requests.get(f"{url_prefix}{item['url']}",headers=header, verify=False)

                if response.status_code == 200:
                    print(f"{item['device-id']} : Downloaded")
                    data = response.json()

                    os.makedirs(bootstrap_directory, exist_ok=True)
                    with open(f"{bootstrap_directory}/{item['device-id']}.cfg","w", newline='\n') as bootstrapfile:
                        bootstrapfile.write(data['bootstrapConfig'])
                    print(f"{item['device-id']} : Saved.")
                    downloaded_filesize = os.path.getsize(f"{bootstrap_directory}/{item['device-id']}.cfg")
                    if downloaded_filesize > 36000:
                        success_dl = success_dl + 1
                else:
                    print(f"{item['device-id']} : Failed : {response.status_code}, {response.reason}")

            print(f"Successfully downloaded (file is bigger than 36kB) [Downloaded/Total]: {success_dl}/{total_dl}")

            if input("Do you want to UPLOAD bootstrap configurations to routers? (y/n):") == "y":
                args.mode = "upload"

        if args.csv and args.mode == "upload":
            print("Current mode is UPLOAD bootstrap configuration to routers")

            total_ul = len(sdwan_data)
            success_ul = 0
            for item in sdwan_data:
                for var in item['variables']:
                    if var['name'] == 'system_ip':
                        system_ip = var['value']
                        break

                if os.path.exists(f"{bootstrap_directory}/{item['device-id']}.cfg"):
                    cmd = f"pscp -pw {vmanage_password} -scp {bootstrap_directory}/{item['device-id']}.cfg {vmanage_username}@{system_ip}:ciscosdwan.cfg"
                    #print(cmd)
                    # exit_code = subprocess.call(cmd.split())
                    # if exit_code == 0:
                    #     print(f"{item['device-id']}.cfg was uploaded successfully.")
                    # else:
                    #     print(f"{item['device-id']}.cfg : Failed: {exit_code}")
                    try:
                        completed = subprocess.run(cmd.split(), capture_output=True, timeout=10, text=True, input='y')
                    except Exception as e:
                        if verbose_level > 0:
                            print(f"ERROR in SCP transfer: {e}")

                    if completed.returncode == 0:
                        print(f"{item['device-id']}.cfg : Upload successful.")
                        success_ul = success_ul + 1
                    else:
                        print(f"{item['device-id']}.cfg : Upload failed. Code: {completed.returncode}")
                else:
                    print(f"{item['device-id']}.cfg : File does not exists. Generate bootstrap configuration.")
            
            print(f"Successfully uploaded to routers. [Uploaded/Total]: {success_ul}/{total_ul}")
            if success_ul<total_ul:
                print("There were failed upload tasks, continue with CHECK mode. Failed uploads can be false alarms.")
                

            if input("Do you want to CHECK bootstrap configurations on routers? (y/n):") == "y":
                args.mode = "check"

        if args.csv and args.mode == "check":
            print("Current mode is CHECK bootstrap configuration on routers")

            total_check = len(sdwan_data)
            success_check = 0
            failed_check = []
            for item in sdwan_data:
                for var in item['variables']:
                    if var['name'] == 'system_ip':
                        system_ip = var['value']
                        break

                
                cmd = f"pscp -pw {vmanage_password} -scp {vmanage_username}@{system_ip}:ciscosdwan.cfg scptest.txt"
                try:
                    completed = subprocess.run(cmd.split(), capture_output=True, timeout=10, text=True, input='y')
                except Exception as e:
                    if verbose_level > 0:
                        print(f"ERROR in SCP transfer: {e}")
                    failed_check.append(system_ip)
                    print(f"{system_ip}: ciscosdwan.cfg is not on device.")
                else:
                    print(f"{system_ip}: ciscosdwan.cfg is on device.")
                    success_check = success_check+1
                    os.remove("scptest.txt") # smazani docasneho souboru pro kotnrolu stazeni ciscosdwan
                        

            
            print(f"Device bootstrap configuration checked on routers [Success/Total]: {success_check}/{total_check}")

            if len(failed_check) > 0:
                print(f"Failed devices:\n {failed_check}")



            if input("Do you want to set TAGs to routers? (y/n):") == "y":
                args.mode = "tag"

        if args.mode == "tag":
            print("Script will tag routers in vManage")
            all_tags = []
            vmanage_url_req = f"/v1/tags"
            response = requests.get(f"{url_prefix}{vmanage_url_req}",headers=header, verify=False)
            if response.status_code == 200:
                data = response.json()
                print("List of existing tags:")    
                for item in data:
                    print(f"Tag ID: {item['id']}, Name: {item['name']}")
                    all_tags.append({'TagId' : item['id'], "name" : item['name'], "tagType": "device"})
            else:
                print(f"Failed to retrieve data. Status Code: {response.status_code}")
                exit()
            if not tag_id:
                while True:
                    tag_id = input("Insert Tag ID: ")
                    if tag_id != "":
                        break
                    print('No input!')
            selected_tags =  [tag for tag in all_tags if tag_id in tag['TagId']]

            print(selected_tags)
            # json_data = {
            #               "associate": [
            #                 {
            #                   "deviceId": "C8K-46dabbc6-ae64-49c1-8fde-01b669ae2aa4",
            #                   "tagList": [
            #                     {
            #                       "name": "tag1",
            #                       "tagId": "1ca0ad1c-ca96-4cba-b33b-4209225e4fdf",
            #                       "tagType": "device"
            #                     },
            #                     {
            #                       "name": "tag2",
            #                       "tagId": "",
            #                       "tagType": "device"
            #                     }
            #                   ]
            #                 }
            #               ],
            #               "create": [
            #                 {
            #                   "name": "tag2",
            #                   "tagId": "",
            #                   "tagType": "device"
            #                 }
            #               ]
            #             }
            json_data = {"data": {"associate":[],"create": []}}
            for item in sdwan_data:
                json_data["data"]["associate"].append({'deviceId' : item['device-id'],"tagList": selected_tags})
            print(f"URL: {url_prefix}{vmanage_url_req}")
            print("JSON data:")
            print(json.dumps(json_data, indent=2))
            
            input("Check JSON and URL and press [enter] to send it to vmanage... (no return after this point )")
            
            # response = requests.post(f"{url_prefix}{vmanage_url_req}",headers=header, json=json_data, verify=False)
            
            if response.status_code == 200:
                print("Successful")
            else:
                exit(f"Failed. Status Code: {response.status_code}, Error message: {response.text}")

    exit("Thank you for using CSOB SD-WAN Bootstrap script.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit("Program canceled [Ctrl+C]")
