**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do.

# Migration guide from API v2 to API v3 - code snippets

This guide is designed to facilitate the migration of your existing tools that are not using the latest version of VirusTotal’s API (v3 from now on) to interact with your services. 
Additionally, it is useful to familiarize you with v3 endpoints, consolidate the basics and improve performance by automating manual tasks.

❗ Please note that some of the use cases make use of auxiliary functions or methods. All of them are implemented on the [Helper methods](#set7) section. For the sake of clarity, the API key used in the code snippets below is configured as an environment variable (VT_APIKEY). For production uses, please use a secure key management system instead.

#### Table of content 

* [Submitting samples, getting file reports, and rescanning files](#set1)
    * [Submit file (smaller than 32MB)](#set1.1)
    * [Submit file (larger than 32MB)](#set1.2)
    * [Get file report](#set1.3)
    * [Rescan file](#set1.4)
* [Getting file behaviour reports and downloading network traffic files](#set2)
    * [Get file behaviour report ](#set2.1)
        * [Get file behaviour report - except API calls](#set2.1.1)
        * [Get file behaviour report - API calls](#set2.1.2)
    * [Download files’s network traffic](#set2.2)
* [Scanning URLs, getting reports for URLs, domains, and IP addresses](#set3)
    * [Scan URL](#set3.1)
    * [Get URL report](#set3.2)
    * [Get domain report](#set3.3)
    * [Get IP address report](#set3.4)
* [Feeds for enrichment](#set4)
    * [Get file feed](#set4.1)
    * [Getting URL feed](#set4.2)
* [Getting file clusters and downloading files](#set5)
    * [Get file clusters](#set5.1)
    * [Download file](#set5.2)
* [Intelligence search via API](#set6)
* [Helper methods](#set7)

## Submitting samples, getting file reports, and rescanning files <a name="set1"></a>

File scanning and report generation functionalities are among VirusTotal’s most popular use cases. Additionally, rescanning files provides information updated over time, which makes it very valuable and places it in the top ranking of must-know resources for threat analysis.

### Submit file (smaller than 32MB) <a name="set1.1"></a>

Similar to v2, there are 2 ways of submitting files to VirusTotal in v3, which are based on file size. When a file is uploaded, it is automatically analyzed without any user action required.
The following code snippet shows how to submit files smaller than 32 MB. The file path is specified and the status of the request is printed out. To check the file analysis result, the file’s report must be requested.

```python
import os
import requests
from helpers import get_file_size

FILE_PATH = 'file_to_submit.exe'

def submit_small_file(file_path):
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

res = submit_small_file(FILE_PATH)
if res is not None and 'data' in res and 'id' in res['data']:
  print(f'You can check the analysis status through '
    f'https://www.virustotal.com/api/v3/analyses/{res["data"]["id"]} endpoint.')

```


### Submit file (larger than 32MB) <a name="set1.2"></a>

Submitting files larger than 32 MB invloves 2 steps:
- Request a specific upload URL using the v3 endpoint: /files/upload_url 
- Send the POST request to the new URL using the v3 endpoint: /files

Once the file is uploaded, it is automatically analyzed without any user input required. The following example demonstrates how to submit files larger than 32 MB in two steps, with the file path specified and the status of the POST request printed out.

❗Please note that if the file is larger than 200 MB you might experience issues. If the sample is a compressed file, try to upload the individual files instead.

```python
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

```

### Get file report <a name="set1.3"></a>

A file’s report is a JSON data structure. For full context on file report structure refer to [File object description](https://developers.virustotal.com/reference/files). The main file report is limited mostly to the file's static properties and AV verdicts. For dynamic properties, refer to the Getting file behaviour report section (link here).

The code snippet below prints the whole JSON main (or static) report of a given file, based on its SHA256 hash. SHA1 and MD5 hashes can also be used to uniquely identify files.

```python
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

```

### Rescan file <a name="set1.4"></a>

Malware detection solutions must keep up with new malware trends and adapt accordingly. Sometimes a sample that was not initially detected as malicious could be classified as such later on based on updates and improvements in detection tools. When malicious files are not detected as malicious during the initial scan, the best approach is to rescan the file and check the report again, especially if the last analysis date is too old.

The following example shows how to rescan a file without having to submit it again. You will need to provide the file hash, and the status of the request will be printed out. Accepted hashes to uniquely identify the file are: SHA256, SHA1 and MD5.

❗Please note that by submitting a file that has already been uploaded to VirusTotal, it will be automatically rescaned.

```python
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
if res and res.get('data', {}).get('type') == 'analysis':
  print(f'You can check the analysis status through '
   f'https://www.virustotal.com/api/v3/analyses/{res["data"]["id"]} endpoint.')

```


## Getting file behaviour reports and downloading network traffic <a name="set2"></a>

In addition to static analyses and AV verdicts, VirusTotal provides results of a second phase analysis process. Samples submitted to VirusTotal are detonated in several sandboxes. Analyzing files this way produces valuable data on their behaviour and artifacts supporting them.

❗Please note that many samples implement anti-sandboxing techniques, so it is not always possible to get all the details. For the same reason, not all sandboxes are going to produce the same output.

### Get file behaviour report <a name="set2.1"></a>

The file behaviour report for v2 is a unique JSON structure covering all data gathered from detonating the sample in a single sandbox (unique integration available).

Unlike v2, v3 provides multiple sandbox integrations, and reports can be provided by sandbox  ([1](https://developers.virustotal.com/reference/get-file-behaviour-id)) or by aggregating the reports from all sandboxes ([2](https://developers.virustotal.com/reference/get-all-behavior-reports-for-a-file)). Another difference is that in v3, the system API calls are not included in the reports. There’s a dedicated endpoint ([Get a detailed HTML behaviour report](https://developers.virustotal.com/reference/get-file-behaviour-html)) for them, which requires the sandbox providing this data to be identified.

❗Please note that not all sandboxes can provide API calls. Refer to [In-house Sandboxes behavioural analysis products](https://support.virustotal.com/hc/en-us/articles/6253253596957-In-house-Sandboxes-behavioural-analysis-products) and [External behavioural engines sandboxes](https://support.virustotal.com/hc/en-us/articles/7904672302877-External-behavioural-engines-sandboxes) that show which sandboxes can provide the “__HTML behaviour report__” under the “**Low Level Report**” feature.

#### Get file behaviour report - except API calls <a name="set2.1.1"></a>

The code snippet below, prints the **summary** of all available sandbox reports of a given file, as a JSON object. The file has to be identified through SHA256, SHA1 or MD5 hashes.

```python
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

```

#### Get file behaviour report - API calls <a name="set2.1.2"></a>

The code snippet below, prints the __HTML Low Level Report__,which includes API calls, based on the activity monitored by specific sandboxes where the file is detonated. It requires file identifier (SHA256, SHA1 or MD5 hash) and sandbox name.

```python
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

```

### Download files’s network traffic <a name="set2.2"></a>

During the file’s sandbox detonation, the network traffic is monitored and stored in a PCAP file. This file can be downloaded for further analysis outside of VirusTotal’s environment.

The code snippet below, stores the PCAP network traffic file of a given file detonation on a given sandbox. The file identifier (SHA256, SHA1 or MD5 hash), a sandbox name, and the desired name for the PCAP file are required. As a result the status of the request is printed out.

```python
import os
import urllib
import requests
from helpers import dump_to_file

FILE_SHA256_HASH = 'd529b406724e4db3defbaf15fcd216e66b9c999831e0b1f0c82899f7f8ef6ee1'
SANDBOX = 'VirusTotal Cuckoofork'
PCAP_FILE_NAME = 'pcapv3.pcap'

def get_network_traffic_pcap(file_hash, sandbox):
  url = f'https://www.virustotal.com/api/v3/file_behaviours/{file_hash}_{urllib.parse.quote(sandbox)}/pcap'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res

res = get_network_traffic_pcap(FILE_SHA256_HASH, SANDBOX)
if dump_to_file(PCAP_FILE_NAME, res):
  print('PCAP file saved.')
```

## Scanning URLs, getting reports for URLs, domains, and IP addresses <a name="set3"></a>

In addition to scanning files, VirusTotal also performs scans on URLs, and extracts associations with domains and IP addresses which are also automatically scanned. Information on these representative infrastructure elements provides a more complete and comprehensive view of the scope of threat campaigns.

### Scan URL <a name="set3.1"></a>

VirusTotal provides a specific endpoint for scanning URLs. The same endpoint can also be used to rescan URLs that are already part of the VirusTotal dataset. Attackers have been seen to take advantage of legitimate infrastructure to perpetrate their attacks, so rescanning is recommended for those suspicious URLs whose last analysis date is very old.

This example shows how to request a URL analysis, which is required and as a result the status of the request is printed out.

To check the analysis result, a URL report must be requested.

```python
import os
from pprint import pprint
import requests

URL_TO_SCAN = 'http://btcmx.net/NDM3MmI3N2Q3OWVkNDgxZHY0Q1VLb1NwcUJEN3NtVy9QeVU2emR6REppWFJxYVdQdDkrZ0NpYXlReUVzeUt5Nmp6N1ZOeHlSRXEySEJmTmE'

def scan_url(payload):
  url = 'https://www.virustotal.com/api/v3/urls'
  headers = {'accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY'], 'content-type': 'application/x-www-form-urlencoded'}
  res = requests.post(url, data=f'url={payload}', headers=headers)
  res.raise_for_status()
  return res.json()

res = scan_url(URL_TO_SCAN)
pprint(res)

```

### Get URL report <a name="set3.2"></a>

A URL’s report is a JSON data structure. For full context on URL report structure refer to [URL object description](https://developers.virustotal.com/reference/url-object).
The code snippet below, prints the whole JSON report of a given URL, that has to be [URL-safe](https://docs.python.org/3/library/base64.html#base64.urlsafe_b64encode) base64 encoded.

```python
import os
from pprint import pprint
import base64
import requests

URL_TO_CHECK = 'https://www.luckypatchers.com/download/'

def get_url_report(url):
  url = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
  url = f'https://www.virustotal.com/api/v3/urls/{url}'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

report = get_url_report(URL_TO_CHECK)
pprint(report)

```


### Get domain report <a name="set3.3"></a>

A domain’s report is a JSON data structure. For full context on domain report structure refer to [Domain object description](https://developers.virustotal.com/reference/domains-1).

The code snippet below prints the whole JSON report for a given domain.

```python
import os
from pprint import pprint
import requests

DOMAIN = 'asfdasdasdasdasddfgdfgasdasd.com'

def get_domain_report(domain):
  url = f'https://www.virustotal.com/api/v3/domains/{domain}'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

report = get_domain_report(DOMAIN)
pprint(report)

```

### Get IP address report <a name="set3.4"></a>

A IP address’s report is a JSON data structure. For full context on IP address report structure refer to [IP address object description](https://developers.virustotal.com/reference/ip-object).

The code snippet below, prints the whole JSON report of a given IP address.

```python
import os
from pprint import pprint
import requests

IP_ADDRESS = '8.8.8.8'

def get_ip_report(ip_address):
  url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

report = get_ip_report(IP_ADDRESS)
pprint(report)

```

## Feeds for enrichment <a name="set4"></a>

VirusTotal provides a continuous real-time stream of JSON-encoded structures that contain information about all new or updated entities. Feeds are very useful for automated IoC generation or giving additional context to historical alerts and investigations.

The JSON-encoded structures are put together in batches that can be generated every minute or hour. The batch consists of a text file containing one JSON structure per line.

While v2 has only one endpoint per entity, v3 has 2 endpoints per entity, one for by minute batches and another one for hourly batches. However, the code snippets below dump bzip2 compressed UTF-8 text files. Each text file contains one **file report** as JSON structure per line. They use a configuration parameter 'PER_MINUTE' that specifies the time-batch to be used:

* By minute considerations
    * PER_MINUTE  parameter must be 'True'
    * v3 endpoint request time parameter format: YYYYMMDDhhmm
    * The most recent batch always has a 60 minutes lag from the current time
* Hourly considerations
    * PER_MINUTE parameter must be 'False'
    * v3 endpoint request time parameter format: YYYYMMDDhh
    * The most recent batch always has a 2 hours lag from the current time
 
The code could be automatically run with a cron job.

❗Please note that a backlog of 7 days is provided at any given point in time. Successful calls to these endpoints will return a 302 redirect response to a URL from which the final batch file will be downloaded.

### Get file feed <a name="set4.1"></a>

```python
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

```

### Getting URL feed <a name="set4.2"></a>



```python
ffrom datetime import timedelta, datetime
import os
import requests
from helpers import dump_to_file

PER_MINUTE = False

TIME = None
if PER_MINUTE:
  TIME = (datetime.utcnow() - timedelta(hours = 1)).strftime('%Y%m%d%H%M')
else:
  TIME = (datetime.utcnow() - timedelta(hours = 2)).strftime('%Y%m%d%H')

def get_url_feed(per_minute, time):
  url = None
  if per_minute:
    url = f'https://www.virustotal.com/api/v3/feeds/urls/{time}'
  else:
    url = f'https://www.virustotal.com/api/v3/feeds/urls/hourly/{time}'
  headers={'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers, stream=True, allow_redirects=True)
  res.raise_for_status()
  return res

res = get_url_feed(PER_MINUTE, TIME)
if dump_to_file(f'{TIME}_url_feeds.bzip2', res):
  print('bzip2 file saved.')

```


## Getting file clusters and downloading files <a name="set5"></a>



### Get file clusters <a name="set5.1"></a>

Clusters are generated for the files submitted over the span of a day, based on VirusTotal’s in-house hash algorithm, Vhash. It takes into account sample properties such as, example using Portable Executables, imports, exports, sections, file size, etc. 

Clusters can be used to detect new prominent malware families, highly polymorphic. Further analysis can provide knowledge around the threat landscape of large crime campaigns.

```python
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

```

### Download file <a name="set5.2"></a>

In addition to getting reports on a file based on its hash, you can also download the file by sending a request to VirusTotal’s file download endpoint. You can choose to receive the file in either JSON or XML format. The response will contain the file content, which you can save to your computer.

In the code snippet below, the get_file function takes the file hash and returns the content of the file after sending a GET request to VT’s download endpoint.


```python
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

```

## Intelligence search via API <a name="set6"></a>

With this endpoint, you can search for IoCs in VirusTotal’s dataset by utilizing the same query syntax used in the VT Intelligence user interface. The endpoint returns a collection of IoCs that match the given query. If you’re solely interested in obtaining the SHA-256 of the matching files, you can set the descriptors_only parameter to true. Setting the descriptors_only parameter to true can also help reduce the latency of your request.

❗Please note that it is important that you use URL Safe encoding when utilizing this endpoint programmatically. 


```python
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

```

## Helper methods <a name="set7"></a>

This section covers auxiliary functions used by the main use cases. 

```python
import logging
import os

def dump_to_file(file_name, response):
  try:
    with open(file_name, 'wb') as fd:
      for chunk in response.iter_content(chunk_size=65536):
        fd.write(chunk)
    return True
  except Exception as ex:
    logging.error(ex)


def get_file_size(file_path):
  try:
    return os.stat(file_path).st_size/(1024*1024)
  except Exception as ex:
    logging.error(ex)

```



