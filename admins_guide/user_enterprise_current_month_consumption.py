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
	Getting current month VT enterprise users consumption.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update GROUP_ID variable. Check out your group ID via web:
		landing page https://www.virustotal.com/gui/home/search -> your name at the top right corner -> VT enterprise group -> GROUP PREFERENCES section -> Group ID
	Update USERS_IDS variable. Add to this list the user ID of users whose month VT enterprise consumption you want to check.
		Get users IDs:
			Check Requirements section of https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md or
			Via API through the getting_group_users_and_service_accounts.py script (username).
		Make the list empty to get all group users consumption.
"""

print(
	"**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do."
)

GROUP_ID = "Your group ID"
USERS_IDS = [
	#'userID1',
	#'userID2'
]


"""
Getting group users ID list (by group ID).
VT API endpoint reference: https://developers.virustotal.com/reference/get-group-users
"""


def get_group_users(group_id):
	users = []
	url = f"https://www.virustotal.com/api/v3/groups/{group_id}/relationships/users"
	headers = {"accept": "application/json", "x-apikey": os.environ["VT_APIKEY"]}

	while url:
		res = requests.get(url, headers=headers)
		res.raise_for_status()
		res = res.json()
		users.extend([e["id"] for e in res["data"]])
		url = res.get("links", {}).get("next", None)
	return users


"""
Getting current month VT enterprise user consumption by user ID.
VT API endpoint reference: https://developers.virustotal.com/reference/get-user-overall-quotas
"""


def get_user_vt_enterprise_consumption(user_id):
	url = f"https://www.virustotal.com/api/v3/users/{user_id}/overall_quotas"
	headers = {"accept": "application/json", "x-apikey": os.environ["VT_APIKEY"]}
	res = requests.get(url, headers=headers)
	res.raise_for_status()
	res = res.json()
	keys = list(res.get("data", {}).keys())
	# remove group related info
	for el in res.get("data", {}):
		if res.get("data", {}).get(el, {}).get("group", None):
			res.get("data", {}).get(el, {}).pop("group")
	return res


def main(users_ids, group_id):
	if len(users_ids) == 0:
		users_ids = get_group_users(group_id)

	for user_id in users_ids:
		print(f"\nUSER: {user_id}")
		pprint(get_user_vt_enterprise_consumption(user_id))


if __name__ == "__main__":
	main(USERS_IDS, GROUP_ID)
