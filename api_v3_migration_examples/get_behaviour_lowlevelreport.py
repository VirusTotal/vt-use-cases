import os
import urllib
import requests
from helpers import dump_to_file

FILE_SHA256_HASH = 'd529b406724e4db3defbaf15fcd216e66b9c999831e0b1f0c82899f7f8ef6ee1'
SANDBOX = 'VirusTotal Jujubox'
REPORT_FILE_NAME = 'myLowLevelReport.html'

def get_behaviour_lowlevelreport(file_hash, sandbox):
  url = f'https://www.virustotal.com/api/v3/file_behaviours/{file_hash}_{urllib.parse.quote(sandbox)}/html'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res

res = get_behaviour_lowlevelreport(FILE_SHA256_HASH, SANDBOX)
if dump_to_file(REPORT_FILE_NAME, res):
  print('Report saved.')
