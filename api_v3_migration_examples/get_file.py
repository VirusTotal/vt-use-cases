import os
import requests
from helpers import dump_to_file

FILE_SHA256_HASH = 'd529b406724e4db3defbaf15fcd216e66b9c999831e0b1f0c82899f7f8ef6ee1'
FILE_NAME = 'downloaded_sample'

def get_file(file_hash):
  url = f'https://www.virustotal.com/api/v3/files/{file_hash}/download'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res

res = get_file(FILE_SHA256_HASH)
if dump_to_file(FILE_NAME, res):
  print('File saved.')
