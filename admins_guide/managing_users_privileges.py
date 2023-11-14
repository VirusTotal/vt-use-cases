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
	Managing group members admin privileges; granting and revoking admin privileges.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update GROUP_ID variable. Check out your group ID via web:
		landing page https://www.virustotal.com/gui/home/search -> your name at the top right corner -> VT enterprise group -> GROUP PREFERENCES section -> Group ID
	Update GRANT_ADMIN_PRIVILEGES_EMAIL_ADDRESSES variable. Add to this list the email addresses of users you want to grant admin privileges to.
	Update REVOKE_ADMIN_PRIVILEGES_USERS_IDS variable. Add to this list the user ID of users you want to revoke admin privileges from.
		Get users IDs:
			Check Requirements section of https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md or
			Via API through the getting_group_users_and_service_accounts.py script (username).
"""

print(
	"**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do."
)

GROUP_ID = "Your group ID"
GRANT_ADMIN_PRIVILEGES_EMAIL_ADDRESSES = [
	"user1@companydomain.com",
	"user2@companydomain.com",
]
REVOKE_ADMIN_PRIVILEGES_USERS_IDS = ["userID1", "userID2"]

"""
Granting admin privileges to a list of users (by their email addresses).
VT API endpoint reference: https://developers.virustotal.com/reference/post-group-administrators
"""


def grant_admin_privileges(group_id, email_addresses):
	url = f"https://www.virustotal.com/api/v3/groups/{group_id}/relationships/administrators"
	headers = {
		"accept": "application/json",
		"x-apikey": os.environ["VT_APIKEY"],
		"content-type": "application/json",
	}
	payload = {"data": [{"type": "user", "id": e} for e in email_addresses]}
	res = requests.post(url, json=payload, headers=headers)
	res.raise_for_status()
	print(f"Admin privileges granted successfully.")


"""
Revoking admin privileges of a user (by its user ID).
VT API endpoint reference: https://developers.virustotal.com/reference/delete-user-group-administrator
"""


def revoke_admin_privileges(group_id, user_id):
	url = f"https://www.virustotal.com/api/v3/groups/{group_id}/relationships/administrators/{user_id}"
	headers = {
		"accept": "application/json",
		"x-apikey": os.environ["VT_APIKEY"],
	}
	res = requests.delete(url, headers=headers)
	res.raise_for_status()
	print(f"Admin privileges revoked successfully for user {user_id}.")


def main(group_id, email_addresses, revoke_admin_privileges_users_ids):
	if len(email_addresses) > 0:
		grant_admin_privileges(group_id, email_addresses)
	for user_id in revoke_admin_privileges_users_ids:
		revoke_admin_privileges(group_id, user_id)


if __name__ == "__main__":
	main(
		GROUP_ID,
		GRANT_ADMIN_PRIVILEGES_EMAIL_ADDRESSES,
		REVOKE_ADMIN_PRIVILEGES_USERS_IDS,
	)
