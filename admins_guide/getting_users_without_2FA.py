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
	Getting the list of users of a group without 2FA, showing the following parameters:
		username, first name, last name and email.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update GROUP_ID variable. Check out your group ID via web:
		landing page https://www.virustotal.com/gui/home/search -> your name at the top right corner -> VT enterprise group -> GROUP PREFERENCES section -> Group ID
"""

print(
	"**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do."
)

GROUP_ID = "Your group ID"

"""
Getting users objects related to a group by group ID, filtering by 2fa_enabled = false.
	Requested users attributes: first_name,last_name,email.
VT API endpoint reference: https://developers.virustotal.com/reference/groups-relationships
"""


def get_users_without_2FA(group_id):
	users = []
	url = f"https://www.virustotal.com/api/v3/groups/{group_id}/users?attributes=first_name,last_name,email&filter=2fa_enabled:false"
	headers = {"accept": "application/json", "x-apikey": os.environ["VT_APIKEY"]}
	while url:
		res = requests.get(url, headers=headers)
		res.raise_for_status()
		res = res.json()
		for el in res["data"]:
			users.append(
				f"username: {el['id']}, first_name: {el['attributes'].get('first_name', '')}, last_name: {el['attributes'].get('last_name', '')}, email: {el['attributes'].get('email', '')}"
			)
		url = res.get("links", {}).get("next", None)
	return users


def main(group_id):
	users_without_2fs = get_users_without_2FA(group_id)
	if len(users_without_2fs) > 0:
		print(f"\nThere are {len(users_without_2fs)} users without 2FA.")
		pprint(users_without_2fs)
	else:
		print("\nNo users without 2FA.")


if __name__ == "__main__":
	main(GROUP_ID)
