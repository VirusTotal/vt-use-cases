import os
from pprint import pprint
import requests

FILE_SHA256_HASH = 'd529b406724e4db3defbaf15fcd216e66b9c999831e0b1f0c82899f7f8ef6ee1'

def get_behaviour_report(file_hash):
  url = f'https://www.virustotal.com/api/v3/files/{file_hash}/behaviours'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

report = get_behaviour_report(FILE_SHA256_HASH)
pprint(report)
