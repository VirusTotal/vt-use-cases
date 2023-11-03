import os
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
	Updating users API daily cap.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update DAILY_LIMIT variable to the allowance of API requests the users are going to be limited to.  
	Update USERS_IDS variable. Add to this list the user ID of users you want to remove from your group.
		Get users IDs via web https://www.virustotal.com/gui/group/virustotal/users or via API through the getting_group_users_and_service_accounts.py script (username).
"""

print('**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do.')

DAILY_LIMIT = 500
USERS_IDS = [
	'userID1',
	'userID2'
]

""" 
Update user (by its user ID) API cap. 
VT API endpoint reference: https://developers.virustotal.com/reference/patch-user-id
"""
def update_api_cap(user_id, daily_limit):
	url = f'https://www.virustotal.com/api/v3/users/{user_id}'
	headers = {
		'accept': 'text/plain',
		'x-apikey': os.environ['VT_APIKEY'],
		'content-type': 'application/json' 
	}
	payload = {'data': {'type': 'user', 'attributes': {'quotas': {'api_requests_daily': {'allowed': daily_limit}}}}}
	print(payload)
	res = requests.patch(url, json=payload, headers=headers)
	res.raise_for_status()
	print(res.status_code)

def main(users_ids, daily_limit):
	for user_id in users_ids:
		update_api_cap(user_id, daily_limit)

if __name__ == "__main__":
	main(USERS_IDS, DAILY_LIMIT)