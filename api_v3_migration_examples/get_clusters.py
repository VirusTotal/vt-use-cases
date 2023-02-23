import os
from pprint import pprint
import requests

DATE = '2022-12-31'

def get_clusters(date):
   url = f'https://www.virustotal.com/api/v3/stats/vhash_clusters?date={date}'
   headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
   res = requests.get(url, headers=headers)
   res.raise_for_status()
   return res.json()

clusters = get_clusters(DATE)
pprint(clusters)