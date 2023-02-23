from datetime import timedelta, datetime
import os
import requests
from helpers import dump_to_file

PER_MINUTE = True

TIME = None
if PER_MINUTE:
    TIME = (datetime.utcnow() - timedelta(hours = 1)).strftime('%Y%m%d%H%M')
else:
    TIME = (datetime.utcnow() - timedelta(hours = 2)).strftime('%Y%m%d%H')

def get_file_feed(per_minute, time):
    url = None
    if per_minute:
        url = f'https://www.virustotal.com/api/v3/feeds/files/{time}'
    else:
        url = f'https://www.virustotal.com/api/v3/feeds/files/hourly/{time}'
    headers={'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers, stream=True, allow_redirects=True)
    res.raise_for_status()
    return res

res = get_file_feed(PER_MINUTE, TIME)
if dump_to_file(f'{TIME}_file_feeds.bzip2', res):
    print('bzip2 file saved.')