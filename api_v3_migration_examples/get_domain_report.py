import os
from pprint import pprint
import requests

DOMAIN = 'asfdasdasdasdasddfgdfgasdasd.com'

def get_domain_report(domain):
   url = f'https://www.virustotal.com/api/v3/domains/{domain}'
   headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
   res = requests.get(url, headers=headers)
   res.raise_for_status()
   return res.json()

report = get_domain_report(DOMAIN)
pprint(report)