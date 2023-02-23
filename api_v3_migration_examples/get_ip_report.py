import os
from pprint import pprint
import requests

IP_ADDRESS = '8.8.8.8'

def get_ip_report(ip_address):
   url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
   headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
   res = requests.get(url, headers=headers)
   res.raise_for_status()
   return res.json()

report = get_ip_report(IP_ADDRESS)
pprint(report)