import requests
import json
import yaml
import csv
from urllib.parse import urlparse
import subprocess
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
            print("Login successful!")
        else:
            print("Login failed!")
            return None

def get_all_config_groups(header):
    url = "https://vman.cz.net.sys/dataservice/v1/config-group"
    response = requests.get(url, headers=header, verify=False)
    response.raise_for_status()
    data = response.json()
    # Handle both dict with 'data' key and direct list response
    groups = data.get('data', []) if isinstance(data, dict) else data
    return groups

def get_config_group_devices(header, config_group_id):
    url = f"https://vman.cz.net.sys/dataservice/v1/config-group/{config_group_id}/device"
    response = requests.get(url, headers=header, verify=False)
    response.raise_for_status()
    data = response.json()
    # Handle both dict with 'data' key and direct list response
    devices = data.get('data', []) if isinstance(data, dict) else data
    return devices

def main():
    os.environ['NO_PROXY'] = 'cz.net.sys'
    # Define vManage information
        
    # ATM vManage
    #vmanage_host = 'vman-atm.cz.net.sys'
    # BRANCHES vManage
    vmanage_host = 'vman.cz.net.sys'
    print(f"Using vManage host: {vmanage_host}")
    vmanage_port = '443'  # Default HTTPS port
    #vmanage_username = input(f"{vmanage_host}\nUsername: ")
    #vmanage_password = getpass("Password: ")
    vmanage_username = 'jf59869'
    vmanage_password = 'BOSCdohledPSU2025'
    bootstrap_directory = "./bootstrap"
    url_prefix = f'https://{vmanage_host}/dataservice'
    verbose_level = 0

    # Authenticate and get session details
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

    # Get all Configuration Groups
    print("\n[INFO] Fetching Configuration Groups...")
    config_groups = get_all_config_groups(header)
    print(f"\nFound {len(config_groups)} Configuration Group(s):\n")
    print(f"{'#':<5} {'Configuration Group ID':<50} {'Name':<30}")
    print("-" * 85)
    
    for index, group in enumerate(config_groups, 1):
        group_id = group.get('id', 'N/A')
        group_name = group.get('name', 'N/A')
        print(f"{index:<5} {group_id:<50} {group_name:<30}")
    
    # Prompt user to select a group
    while True:
        try:
            selection = int(input("\nEnter the number of the Configuration Group to view devices: "))
            if 1 <= selection <= len(config_groups):
                selected_group = config_groups[selection - 1]
                selected_group_id = selected_group.get('id')
                selected_group_name = selected_group.get('name', 'N/A')
                break
            else:
                print(f"[ERROR] Please enter a number between 1 and {len(config_groups)}")
        except ValueError:
            print("[ERROR] Invalid input. Please enter a valid number.")
    
    # Get devices from selected Configuration Group
    print(f"\n[INFO] Fetching devices from Configuration Group: {selected_group_name} ({selected_group_id})")
    devices = get_config_group_devices(header, selected_group_id)
    print(f"\nConfiguration Group Devices - {selected_group_name} ({selected_group_id}):")
    print(f"Found {len(devices)} device(s).\n")
    print(f"{'UUID':<40} {'Device Name':<30}")
    print("-" * 70)
    
    for device in devices:
        device_uuid = device.get('uuid', 'N/A')
        device_name = device.get('hostname', 'N/A')
        print(f"{device_uuid:<40} {device_name:<30}")






if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit("Program canceled [Ctrl+C]")
    except Exception as e:
        exit(f"[ERROR] Program terminated with error:\n{e}")
