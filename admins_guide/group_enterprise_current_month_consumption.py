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
	Getting current month VT enterprise group consumption.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update USER_ID variable with your user ID or your API key:
		User ID via https://www.virustotal.com/gui/group/virustotal/users or via API through the getting_group_users_and_service_accounts.py script (username)).
		API key via https://www.virustotal.com/gui/user/alexandraam/apikey or os.environ['VT_APIKEY'].
"""

print(
	"**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do."
)

USER_ID = os.environ["VT_APIKEY"]

"""
Getting current month VT enterprise group consumption by user ID or user API key.
VT API endpoint reference: https://developers.virustotal.com/reference/get-user-overall-quotas
"""


def get_group_enterprise_current_month_consumption(user_id):
	url = f"https://www.virustotal.com/api/v3/users/{user_id}/overall_quotas"
	headers = {"accept": "application/json", "x-apikey": os.environ["VT_APIKEY"]}
	res = requests.get(url, headers=headers)
	res.raise_for_status()
	res = res.json()
	keys = list(res.get("data", {}).keys())
	# remove user related info
	for el in res.get("data", {}):
		if res.get("data", {}).get(el, {}).get("user", None):
			res.get("data", {}).get(el, {}).pop("user")
	# remove not group related info
	for key in keys:
		if not res.get("data", {}).get(key, {}).get("group", None):
			res.get("data", {}).pop(key)
	sumarry = (
		f"\tSearches {res['data']['intelligence_searches_monthly']['group']['used']}/{res['data']['intelligence_searches_monthly']['group']['allowed']}\n"
		+ f"\tDownloads {res['data']['intelligence_downloads_monthly']['group']['used']}/{res['data']['intelligence_downloads_monthly']['group']['allowed']}\n"
		+ f"\tLivehunt rules {res['data']['intelligence_hunting_rules']['group']['used']}/{res['data']['intelligence_hunting_rules']['group']['allowed']}\n"
		+ f"\tRetrohunt {res['data']['intelligence_retrohunt_jobs_monthly']['group']['used']}/{res['data']['intelligence_retrohunt_jobs_monthly']['group']['allowed']}\n"
		+ f"\tDiff {res['data']['intelligence_vtdiff_creation_monthly']['group']['used']}/{res['data']['intelligence_vtdiff_creation_monthly']['group']['allowed']}\n"
		+ f"\tPrivate scanning {res['data']['private_scans_monthly']['group']['used']}/{res['data']['private_scans_monthly']['group']['allowed']}\n"
	)
	return sumarry, res


def main(user_id):
	summary, breakdown = get_group_enterprise_current_month_consumption(user_id)
	print(f"\nGroup Enterprise consumption summary:")
	print(summary)
	print(f"\nGroup Enterprise consumption breakdown:")
	pprint(breakdown)


if __name__ == "__main__":
	main(USER_ID)
