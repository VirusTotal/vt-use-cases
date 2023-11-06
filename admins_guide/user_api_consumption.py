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
	Getting VT API user consumption between 2 dates.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update START_DATE variable to the start day you want to check user API consumption. Please note that available data includes only the last 60 natural days.
	Update LAST_DATE variable to the final day you want to check user API consumption. Please note that available data includes only the last 60 natural days.
	Update USERS_IDS variable with the user ID whose API consumption you want to check.
		Get users IDs via web https://www.virustotal.com/gui/group/virustotal/users or via API through the getting_group_users_and_service_accounts.py script (username).
"""

print('**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do.')

USER_ID = 'userID'
START_DATE = '20230901'
LAST_DATE = '20230926'

""" 
Getting VT API user consumption between 2 dates (by user ID). Please note that available data includes only the last 60 natural days so your range dates have to be part of the last 60 natural days.
VT API endpoint reference: https://developers.virustotal.com/reference/user-api-usage
"""
def get_user_api_consumption(user_id, start_date, last_date):
	url = f'https://www.virustotal.com/api/v3/users/{user_id}/api_usage?start_date={start_date}&end_date={last_date}'
	headers = {
		'accept': 'application/json',
		'x-apikey': os.environ['VT_APIKEY']
	}
	res = requests.get(url, headers=headers)
	res.raise_for_status()
	res = res.json()
	return res


def main(user_id, start_date, last_date):
	pprint(get_user_api_consumption(user_id, start_date, last_date))

if __name__ == "__main__":
	main(USER_ID, START_DATE, LAST_DATE)