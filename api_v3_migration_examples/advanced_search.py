import os
from pprint import pprint
import urllib
import requests

QUERY = 'entity:file attack_technique:T1055 p:10+ fs:2023-02-19+'

def advanced_search(query):
  url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&limit=10&descriptors_only=false'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

res = advanced_search(QUERY)
pprint(res)
