import os
from pprint import pprint
import requests

"""
**DISCLAIMER:** 
	Please note that this code is for educational purposes only. 
	It is not intended to be run directly in production. 
	This is provided on a best effort basis. 
	Please make sure the code you run does what you expect it to do.
"""

"""
DESCRIPTION
	Getting VT API group consumption between 2 dates.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update START_DATE variable to the start day you want to check group API consumption. Please note that available data includes only the last 60 natural days.
	Update LAST_DATE variable to the final day you want to check group API consumption. Please note that available data includes only the last 60 natural days.
	Update GROUP_ID variable. Check out your group ID here: https://www.virustotal.com/gui/group/virustotal/users
"""

print('**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do.')

GROUP_ID = 'Your group ID'
START_DATE = '20230901'
LAST_DATE = '20230926'

""" 
Getting VT API group consumption between 2 dates (by group ID). Please note that available data includes only the last 60 natural days so your range dates have to be part of the last 60 natural days.
VT API endpoint reference: https://developers.virustotal.com/reference/group-api-usage
"""
def get_group_api_consumption(group_id, start_date, last_date):
	url = f'https://www.virustotal.com/api/v3/groups/{group_id}/api_usage?start_date={start_date}&end_date={last_date}'
	headers = {
		'accept': 'application/json',
		'x-apikey': os.environ['VT_APIKEY']
	}
	res = requests.get(url, headers=headers)
	res.raise_for_status()
	res = res.json()
	return res


def main(group_id, start_date, last_date):
	pprint(get_group_api_consumption(group_id, start_date, last_date))

if __name__ == "__main__":
	main(GROUP_ID, START_DATE, LAST_DATE)