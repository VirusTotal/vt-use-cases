import os
import requests

FILE_SHA256_HASH = 'dbdb558b60ab562296ec2e4f8d34c98f6593a8ffa100b30e54139e1d1409bc8d'

def rescan_file(file_hash):
   url = f'https://www.virustotal.com/api/v3/files/{file_hash}/analyse'
   headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
   res = requests.post(url, headers=headers)
   res.raise_for_status()
   return res.json()

res = rescan_file(FILE_SHA256_HASH)
if res is not None and 'data' in res and 'type' in res['data'] and 'id' in res['data'] and res['data']['type'] == 'analysis':
   print(f'You can check the analysis status through https://www.virustotal.com/api/v3/analyses/{res["data"]["id"]} endpoint.')
else:
   print('File couldn\'t be rescanned')