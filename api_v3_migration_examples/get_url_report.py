import os
from pprint import pprint
import base64
import requests

URL_TO_CHECK = 'https://www.luckypatchers.com/download/'

def get_url_report(url):
   url = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
   url = f'https://www.virustotal.com/api/v3/urls/{url}'
   headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
   res = requests.get(url, headers=headers)
   res.raise_for_status()
   return res.json()

report = get_url_report(URL_TO_CHECK)
pprint(report)