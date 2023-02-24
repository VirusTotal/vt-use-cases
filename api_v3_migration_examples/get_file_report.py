import os
from pprint import pprint
import requests

FILE_SHA256_HASH = 'd01f0af65ccff0a2465a657a691a90d4e7bfd0f1a1430cea74f05415bcc5e795'

def get_file_report(file_hash):
  url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

report = get_file_report(FILE_SHA256_HASH)
pprint(report)
