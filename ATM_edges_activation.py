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

def get_wan_edges(header, url_prefix):
    url = f"{url_prefix}/device"
    response = requests.get(url, headers=header, verify=False)
    response.raise_for_status()
    devices = response.json().get('data', [])
    # Filter for WAN Edge devices (typically 'vedge' type)
    wan_edges = [d for d in devices if d.get('device-type', '').lower() == 'vedge']
    return wan_edges

def get_cert_validity(header, url_prefix, uuid):
    url = f"{url_prefix}/certificate/vedge?uuid={uuid}"
    response = requests.get(url, headers=header, verify=False)
    response.raise_for_status()
    cert_info = response.json()
    # 'validityNotBefore' is usually the field for validity start date
    return cert_info.get('validityNotBefore', '')

def get_all_cert_validities(header, url_prefix):
    url = f"{url_prefix}/certificate/vedge/list"
    response = requests.get(url, headers=header, verify=False)
    response.raise_for_status()
    certs = response.json().get('data', [])
    # Map serialNumber to validity dates
    cert_map = {}
    for cert in certs:
        serial = cert.get('serialNumber') or cert.get('chasisNumber')
        validity_from = cert.get('validityNotBefore', '')
        validity_to = cert.get('validityNotAfter', '')
        cert_map[serial] = (validity_from, validity_to)
    return cert_map

def main():
    os.environ['NO_PROXY'] = 'cz.net.sys'
    # Define vManage information
    vmanage_host = 'vman-atm.cz.net.sys'
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

     # Get WAN edges
    wan_edges = get_wan_edges(header, url_prefix)
    print(f"Found {len(wan_edges)} WAN edges.")

    # Get all certificate validities
    cert_map = get_all_cert_validities(header, url_prefix)

    # Collect validity info
    results = []
    for edge in wan_edges:
        name = edge.get('host-name', edge.get('system-ip', 'unknown'))
        serial = edge.get('chassisNumber') or edge.get('serialNumber')
        validity_from, _ = cert_map.get(serial, ('', ''))
        print(f"WAN Edge: {name}, Edge ID: {serial}, Validity From: {validity_from}")
        results.append([name, serial, validity_from])
        print("WAN Edge raw data:", edge)

    # Print all certificate serials in the map
    for cert in cert_map:
        print("Certificate serial in map:", cert)

    # Write to CSV
#    with open('ATM-edges-validity-from.csv', 'w', newline='') as csvfile:
#        writer = csv.writer(csvfile)
#        writer.writerow(['WAN Edge Name', 'EdgeID', 'Validity From Date'])
#        writer.writerows(results)
   
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit("Program canceled [Ctrl+C]")
    except Exception as e:
        exit(f"[ERROR] Program terminated with error:\n{e}")
