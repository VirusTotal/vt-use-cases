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
	Getting the list of userss and service accounts of a group, specifically the following parameters:
		username, first name, last name, email and type to identify whether it is a user account or a service account
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update GROUP_ID variable. Check out your group ID here: https://www.virustotal.com/gui/group/virustotal/users 
"""

print('**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do.')

GROUP_ID = 'Your group ID'

""" 
Getting group users by group ID.
VT API endpoint reference: https://developers.virustotal.com/reference/get-group-users
"""
def get_users_list(group_id):
	users = []
	url = f'https://www.virustotal.com/api/v3/groups/{group_id}/relationships/users'
	headers = {
		'accept': 'application/json',
		'x-apikey': os.environ['VT_APIKEY']
	}
	while url:
		res = requests.get(url, headers=headers)
		res.raise_for_status()
		res = res.json()
		users = users + res.get('data',[])
		if res.get('links',{}).get('next', None):
			url = res.get('links',{}).get('next', None)
		else:
			url = None
	return users

""" 
Getting user additional info:
	first name, last name and emial 
VT API endpoint reference: https://developers.virustotal.com/reference/user
"""
def get_user_info(user_id):
	url = f'https://www.virustotal.com/api/v3/users/{user_id}'
	headers = {
		'accept': 'application/json',
		'x-apikey': os.environ['VT_APIKEY']
	}
	res = requests.get(url, headers=headers)
	res.raise_for_status()
	res = res.json()
	first_name = res['data']['attributes'].get('first_name', None)
	last_name = res.get('data',{}).get('attributes',{}).get('last_name', None)
	email = res.get('data',{}).get('attributes',{}).get('email', None)
	return first_name, last_name, email

""" Generate group users dictionary showing specific info"""
def get_users(group_id):
	users = []
	users_list = get_users_list(group_id)
	for user in users_list:
		username = user.get('id',None)
		user_type = user.get('type',None)
		first_name, last_name, email = get_user_info(username)
		if (username and first_name and last_name and email and user_type):
				users.append({
					'username': username,
					'first_name': first_name,
					'last_name': last_name,
					'email': email,
					'type': user_type
				})
	return users

""" 
Getting group service accounts 
VT API endpoint reference: https://developers.virustotal.com/reference/get-service-accounts-of-a-group
"""
def get_service_accounts_list(group_id):
	service_accounts = []
	url = f'https://www.virustotal.com/api/v3/groups/{group_id}/relationships/service_accounts'
	headers = {
		'accept': 'application/json',
		'x-apikey': os.environ['VT_APIKEY']
	}
	while url:
		res = requests.get(url, headers=headers)
		res.raise_for_status()
		res = res.json()
		service_accounts = service_accounts + res.get('data',[])
		if res.get('links',{}).get('next', None):
			url = res.get('links',{}).get('next', None)
		else:
			url = None
	return service_accounts

""" 
Getting service account additional info:
	emial 
VT API endpoint reference: https://developers.virustotal.com/reference/get-a-service-account-object
"""
def get_service_account_email(service_account_id):
	url = f'https://www.virustotal.com/api/v3/service_accounts/{service_account_id}'
	headers = {
		'accept': 'application/json',
		'x-apikey': os.environ['VT_APIKEY']
	}
	res = requests.get(url, headers=headers)
	res.raise_for_status()
	res = res.json()
	email = res.get('data',{}).get('attributes',{}).get('email', None)
	return email

""" Generate group service accounts dictionary showing specific info"""
def get_service_accounts(group_id):
	service_accounts = []
	service_accounts_list = get_service_accounts_list(group_id)
	for service_account in service_accounts_list:
		username = service_account.get('id',None)
		user_type = service_account.get('type',None)
		email = get_service_account_email(username)
		if (username and email and user_type):
				service_accounts.append({
					'username': username,
					'first_name': '',
					'last_name': '',
					'email': email,
					'type': user_type
				})
	return service_accounts

def main(group_id):
	users = get_users(group_id)
	pprint(users)
	service_accounts = get_service_accounts(group_id)
	pprint(service_accounts)

if __name__ == "__main__":
	main(GROUP_ID)