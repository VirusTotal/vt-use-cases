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
	Getting the list of administrators of a group probably not authorized to have admin privileges, showing the following parameters:
		username, first name, last name and email.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update GROUP_ID variable. Check out your group ID via web:
		landing page https://www.virustotal.com/gui/home/search -> your name at the top right corner -> VT enterprise group -> GROUP PREFERENCES section -> Group ID
	Update AUTHORIZED_ADMINS_IDs variable. Add to this list the user ID of users you already have confirmed that they need admin privileges.
		Get users IDs:
			Check Requirements section of https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md or
			Via API through the getting_group_users_and_service_accounts.py script (username).
"""

print(
	"**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do."
)

GROUP_ID = "Your group ID"
AUTHORIZED_ADMINS_IDs = ["userID1", "userID2"]

"""
Getting users objects (administrators) related to a group by group ID.
	Requested users attributes: first_name,last_name,email.
VT API endpoint reference: https://docs.virustotal.com/reference/get-group-administrators
"""


def get_possible_unauthorized_admins(group_id, authorized_admins):
	unauthorized_admins = []
	url = f"https://www.virustotal.com/api/v3/groups/{group_id}/administrators?attributes=first_name,last_name,email"
	headers = {"accept": "application/json", "x-apikey": os.environ["VT_APIKEY"]}
	while url:
		res = requests.get(url, headers=headers)
		res.raise_for_status()
		res = res.json()
		for el in res["data"]:
			if el["id"] not in authorized_admins:
				unauthorized_admins.append(
					f"username: {el['id']}, first_name: {el['attributes'].get('first_name', '')}, last_name: {el['attributes'].get('last_name', '')}, email: {el['attributes'].get('email', '')}"
				)
		url = res.get("links", {}).get("next", None)
	return unauthorized_admins


def main(group_id, authorized_admins):
	unauthorized_admins = get_possible_unauthorized_admins(group_id, authorized_admins)
	if len(unauthorized_admins) > 0:
		print(
			f"\nThere are {len(unauthorized_admins)} possible anomalies (users with admin privileges)."
		)
		pprint(unauthorized_admins)
	else:
		print("\nNo anomalies found.")


if __name__ == "__main__":
	main(GROUP_ID, AUTHORIZED_ADMINS_IDs)
