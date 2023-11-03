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
	Removing user members from your VirusTotal group by their user IDs.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update GROUP_ID variable. Check out your group ID here: https://www.virustotal.com/gui/group/virustotal/users 
	Update USERS_IDS variable. Add to this list the user ID of users you want to remove from your group.
		Get users IDs via web https://www.virustotal.com/gui/group/virustotal/users or via API through the getting_group_users_and_service_accounts.py script (username).
"""

print('**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do.')

GROUP_ID = 'Your group ID'
USERS_IDS = [
	'userID1',
	'userID2'
]

""" 
Removing user (by its user ID) from VirusTotal group. 
VT API endpoint reference: https://developers.virustotal.com/reference/delete-user-from-group
"""
def remove_user_from_group(group_id, user_id):
	url = f'https://www.virustotal.com/api/v3/groups/{group_id}/relationships/users/{user_id}'
	headers = {
		'accept': 'text/plain',
		'x-apikey': os.environ['VT_APIKEY']
	}
	res = requests.delete(url, headers=headers)
	res.raise_for_status()
	print(res.status_code)

def main(group_id, users_ids):
	for user_id in users_ids:
		remove_user_from_group(group_id, user_id)

if __name__ == "__main__":
	main(GROUP_ID, USERS_IDS)