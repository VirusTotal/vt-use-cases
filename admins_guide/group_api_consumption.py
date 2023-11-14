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
	Getting VT API group consumption between 2 dates.
REQUIREMENTS
	Admin privileges -> API key as VT_APIKEY environment variable (os.environ['VT_APIKEY'])
	Update START_DATE variable to the start day (yyyymmdd format) you want to check group API consumption. Please note that available data includes only the last 60 natural days.
	Update LAST_DATE variable to the final day (yyyymmdd format) you want to check group API consumption. Please note that available data includes only the last 60 natural days.
	Update GROUP_ID variable. Check out your group ID via web:
		landing page https://www.virustotal.com/gui/home/search -> your name at the top right corner -> VT enterprise group -> GROUP PREFERENCES section -> Group ID
"""

print(
	"**DISCLAIMER:** Please note that this code is for educational purposes only. It is not intended to be run directly in production. This is provided on a best effort basis. Please make sure the code you run does what you expect it to do."
)

GROUP_ID = "Your group ID"
START_DATE = "20230901"
LAST_DATE = "20230926"

"""
Getting VT API group consumption between 2 dates (by group ID). Please note that available data includes only the last 60 natural days so your range dates have to be part of the last 60 natural days.
VT API endpoint reference: https://developers.virustotal.com/reference/group-api-usage
"""


def get_group_api_consumption(group_id, start_date, last_date):
	url = f"https://www.virustotal.com/api/v3/groups/{group_id}/api_usage?start_date={start_date}&end_date={last_date}"
	headers = {"accept": "application/json", "x-apikey": os.environ["VT_APIKEY"]}
	res = requests.get(url, headers=headers)
	res.raise_for_status()
	res = res.json()
	# remove not consuming endpoints
	res["data"].pop("daily_endpoints_not_consuming_quota")
	# remove days with no consumption
	keys = list(res["data"]["daily"].keys())
	for key in keys:
		if not res["data"]["daily"].get(key):
			res["data"]["daily"].pop(key)
	total = sum(res["data"]["total"][e] for e in res["data"]["total"])

	return (
		total,
		res["data"]["total"],
		res["data"]["daily"],
		res["data"]["total_endpoints_not_consuming_quota"],
	)


def main(group_id, start_date, last_date):
	(
		total,
		by_endpoint,
		by_endpoint_and_day,
		by_endpoint_not_consuming,
	) = get_group_api_consumption(group_id, start_date, last_date)
	if total > 0:
		print(f"\nTOTAL {group_id} group API consumption: {total}")
		print(f"\nConsumption API endpoint breakdown:")
		pprint(by_endpoint)
		print(f"\nConsumption API endpoint-day breakdown:")
		pprint(by_endpoint_and_day)
		print(f"\nNot consuming API endpoint breakdown:")
		pprint(by_endpoint_not_consuming)
	else:
		print(
			f"\nThe {group_id} has 0 API consumption between {start_date} and {last_date}."
		)


if __name__ == "__main__":
	main(GROUP_ID, START_DATE, LAST_DATE)
