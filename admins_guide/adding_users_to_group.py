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
	Adding new members to your VirusTotal group by their email address.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update GROUP_ID variable. Check out your group ID here: https://www.virustotal.com/gui/group/virustotal/users 
	Update EMAIL_ADDRESSES variable. Add to this list the email addresses of users you want to make members of your group.
"""

print('**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do.')

GROUP_ID = 'Your group ID'
EMAIL_ADDRESSES = [
	'user1@companydomain.com',
	'user2@companydomain.com'
]

""" 
Adding users (by their email addresses) to VirusTotal group. 
VT API endpoint reference: https://developers.virustotal.com/reference/update-group-users
"""
def add_users_to_group(group_id, email_addresses):
	url = f'https://www.virustotal.com/api/v3/groups/{group_id}/relationships/users'
	headers = {
		'accept': 'application/json',
		'x-apikey': os.environ['VT_APIKEY'],
		'content-type': 'application/json'
	}
	payload = {'data': [{'type':'user','id': e} for e in email_addresses]}
	res = requests.post(url, json=payload, headers=headers)
	res.raise_for_status()
	print('Users added successfully to the group.')


def main(group_id, email_addresses):
	if len(email_addresses) > 0:
		add_users_to_group(group_id, email_addresses)

if __name__ == "__main__":
	main(GROUP_ID, EMAIL_ADDRESSES)