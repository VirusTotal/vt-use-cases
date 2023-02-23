import os
from pprint import pprint
import requests

URL_TO_SCAN = 'http://btcmx.net/NDM3MmI3N2Q3OWVkNDgxZHY0Q1VLb1NwcUJEN3NtVy9QeVU2emR6REppWFJxYVdQdDkrZ0NpYXlReUVzeUt5Nmp6N1ZOeHlSRXEySEJmTmE'

def scan_url(payload):
   url = 'https://www.virustotal.com/api/v3/urls'
   headers = {'accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY'], 'content-type': 'application/x-www-form-urlencoded'}
   res = requests.post(url, data=f'url={payload}', headers=headers)
   res.raise_for_status()
   return res.json()

res = scan_url(URL_TO_SCAN)
pprint(res)