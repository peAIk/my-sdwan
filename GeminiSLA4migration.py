import requests
import json
import os
import csv
from getpass import getpass
import glob
requests.packages.urllib3.disable_warnings()

class Authentication:
    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = f"https://{vmanage_host}:{vmanage_port}"
        url = base_url + api
        payload = {'j_username' : username, 'j_password' : password}

        response = requests.post(url=url, data=payload, verify=False)
        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")
            return jsessionid[0]
        except KeyError:
            print("[ERROR] No valid JSESSION ID returned. Check credentials.")
            exit()

    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = f"https://{vmanage_host}:{vmanage_port}"
        api = "/dataservice/client/token"
        url = base_url + api
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return response.text
        else:
            print("[ERROR] Failed to obtain token.")
            return None

def get_all_devices(header, url_prefix):
    url = f"{url_prefix}/device"
    response = requests.get(url, headers=header, verify=False)
    response.raise_for_status()
    return response.json().get('data', [])

def get_all_config_groups(header, url_prefix):
    url = f"{url_prefix}/v1/config-group"
    response = requests.get(url, headers=header, verify=False)
    response.raise_for_status()
    data = response.json()
    return data.get('data', []) if isinstance(data, dict) else data

def get_config_group_devices(header, url_prefix, config_group_id):
    url = f"{url_prefix}/v1/config-group/{config_group_id}/device/associate"
    response = requests.get(url, headers=header, verify=False)
    response.raise_for_status()
    data = response.json()
    return data.get('devices', []) if isinstance(data, dict) else data

def associate_devices_to_group(header, url_prefix, config_group_id, device_ids):
    url = f"{url_prefix}/v1/config-group/{config_group_id}/device/associate"
    payload = {"devices": [{"id": dev_id} for dev_id in device_ids]}
    response = requests.post(url, headers=header, json=payload, verify=False)
    response.raise_for_status()
    return response.json()

def deploy_config_group(header, url_prefix, config_group_id, csv_path):
    url = f"{url_prefix}/v1/config-group/{config_group_id}/device/deploy"
    with open(csv_path, 'r') as f:
        # Assuming the CSV has headers and is in the format vManage expects
        csv_content = f.read()
    
    # This part of the API is tricky. You might need to adjust headers
    # and payload format based on the exact API requirements for CSV uploads.
    # The 'Content-Type' might need to be 'multipart/form-data'.
    # This is a simplified example.
    
    # For now, we will assume the API accepts a JSON payload with the csvData
    csv_payload = {
        "csvData": csv_content
    }

    response = requests.post(url, headers=header, json=csv_payload, verify=False)
    response.raise_for_status()
    return response.json()

def main():
    os.environ['NO_PROXY'] = 'cz.net.sys'
    vmanage_host = 'vman.cz.net.sys'
    vmanage_port = '443'
    vmanage_username = 'jf59869'
    vmanage_password = 'BOSCdohledPSU2025'
    url_prefix = f'https://{vmanage_host}/dataservice'

    print(f"Using vManage host: {vmanage_host}")
    try:
        auth = Authentication()
        jsessionid = auth.get_jsessionid(vmanage_host, vmanage_port, vmanage_username, vmanage_password)
        token = auth.get_token(vmanage_host, vmanage_port, jsessionid)
    except Exception as e:
        exit(f"[ERROR] Authentication failed: {e}")

    if token:
        header = {'Content-Type': "application/json", 'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
        print("[INFO] Login successful")
    else:
        exit("[ERROR] Could not log in.")

    # 1. Get WAN Edge Hostnames
    hostnames_input = input("Enter WAN edge hostnames separated by commas: ")
    target_hostnames = {h.strip() for h in hostnames_input.split(',')}

    # 2. Get all devices and find the ones we care about
    print("\n[INFO] Fetching all devices...")
    all_devices = get_all_devices(header, url_prefix)
    target_devices = {dev['uuid']: dev for dev in all_devices if dev.get('host-name') in target_hostnames}
    
    if not target_devices:
        print("[WARNING] No devices found for the given hostnames.")
        exit()
    
    print(f"[INFO] Found {len(target_devices)} devices matching hostnames.")
    for dev in target_devices.values():
        print(f"  - {dev['host-name']} (UUID: {dev['uuid']})")


    # 3. Choose Configuration Group
    print("\n[INFO] Fetching Configuration Groups...")
    config_groups = get_all_config_groups(header, url_prefix)
    print(f"\nFound {len(config_groups)} Configuration Group(s):\n")
    print(f"{'#':<5} {'Name':<30} {'ID':<50}")
    print("-" * 85)
    for i, group in enumerate(config_groups, 1):
        print(f"{i:<5} {group.get('name', 'N/A'):<30} {group.get('id', 'N/A'):<50}")

    while True:
        try:
            selection = int(input("\nEnter the number of the target Configuration Group: "))
            if 1 <= selection <= len(config_groups):
                selected_group = config_groups[selection - 1]
                break
            else:
                print(f"[ERROR] Please enter a number between 1 and {len(config_groups)}")
        except ValueError:
            print("[ERROR] Invalid input. Please enter a valid number.")

    selected_group_id = selected_group['id']
    selected_group_name = selected_group['name']
    print(f"\n[INFO] Selected Group: {selected_group_name} ({selected_group_id})")

    # 4. Associate Devices if needed
    print("\n[INFO] Checking device associations...")
    existing_devices = get_config_group_devices(header, url_prefix, selected_group_id)
    existing_device_ids = {dev['id'] for dev in existing_devices}
    
    devices_to_add_ids = [uuid for uuid in target_devices.keys() if uuid not in existing_device_ids]

    if devices_to_add_ids:
        print(f"[INFO] Associating {len(devices_to_add_ids)} new devices to the group...")
        for dev_id in devices_to_add_ids:
             print(f"  - Associating {target_devices[dev_id]['host-name']}")
        try:
            associate_devices_to_group(header, url_prefix, selected_group_id, devices_to_add_ids)
            print("[INFO] Association successful.")
        except Exception as e:
            print(f"[ERROR] Failed to associate devices: {e}")
    else:
        print("[INFO] All target devices are already associated with the group.")

    # 5. Deploy Configuration Group with CSV
    print("\n[INFO] Preparing to deploy configuration group...")
    csv_files = glob.glob('*.csv')
    if not csv_files:
        print("[ERROR] No CSV files found in the current directory.")
        exit()

    print("\nAvailable CSV files:")
    for i, filename in enumerate(csv_files, 1):
        print(f"{i}: {filename}")

    while True:
        try:
            selection = int(input("\nEnter the number of the CSV file to use for deployment: "))
            if 1 <= selection <= len(csv_files):
                selected_csv = csv_files[selection - 1]
                break
            else:
                print(f"[ERROR] Please enter a number between 1 and {len(csv_files)}")
        except ValueError:
            print("[ERROR] Invalid input. Please enter a valid number.")
            
    print(f"\n[INFO] Deploying group '{selected_group_name}' with variables from '{selected_csv}'...")
    
    try:
        # Note: The deploy API with CSV can be complex.
        # This is a placeholder for the actual deployment call.
        # You may need to investigate the exact API endpoint and payload format for CSV upload.
        print("[WARNING] The deploy_config_group function is a placeholder.")
        print("[INFO] Please verify the deployment in vManage.")
        # deploy_config_group(header, url_prefix, selected_group_id, selected_csv)
        # print("[INFO] Deployment initiated successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to deploy configuration group: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Program canceled by user.")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")
