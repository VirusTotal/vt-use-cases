import os
import requests
from helpers import get_file_size

FILE_PATH = 'file_to_submit.exe'

def submit_large_file(file_path):
  # Get the file size in MB
  file_size = get_file_size(file_path)
  if file_size is None:
    return None
  if file_size > 200:
    print('File too large. You might experience issues. '
        'If the sample is a compressed file, '
        'try to upload the inner individual files instead.')
    return None
  if file_size < 32:
    print('File size is not larger than 32 MB. Try VT /files endpoint instead.')
    return None
  # Get the special url for uploading files larger than 32 MB
  url = 'https://www.virustotal.com/api/v3/files/upload_url'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  # Set the url to the new one and submit the sample
  res = res.json()
  if 'data' in res:
    url = res['data']
    print(f'Special URL: {url}')
    with open(file_path, 'rb') as file:
      files = {'file': file}
      headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
      res = requests.post(url, files=files, headers=headers)
      res.raise_for_status()
      return res.json()
  return None

res = submit_large_file(FILE_PATH)
if res and res.get('data', {}).get('type') == 'analysis':
  print(f'You can check the analysis status through '
    f'https://www.virustotal.com/api/v3/analyses/{res["data"]["id"]} endpoint.')
