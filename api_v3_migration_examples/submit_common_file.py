import os
import requests

FILE_PATH = '/content/file_to_submit.exe'

def submit_common_file(file_path):
   # Get the file size in MB
   file_size = get_file_size(file_path)
   if file_size is None:
       return None
   if file_size > 32 :
       print('File size is larger than 32 MB. Try VT /file/upload_url endpoint instead.')
       return None
   with open(file_path, 'rb') as file:
       url = 'https://www.virustotal.com/api/v3/files'
       files = {'file': file}
       headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
       res = requests.post(url, files=files, headers=headers)
       res.raise_for_status()
       return res.json()

res = submit_common_file(FILE_PATH)
if res is not None and 'data' in res and 'id' in res['data']:
   print(f'You can check the analysis status through https://www.virustotal.com/api/v3/analyses/{res["data"]["id"]} endpoint.')
else:
   print('File coulden\'t be submitted.')