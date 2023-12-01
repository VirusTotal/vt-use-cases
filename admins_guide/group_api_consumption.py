"""
**DISCLAIMER:**
    Please note that this code is for educational purposes only.
    It is not intended to be run directly in production.
    This is provided on a best effort basis.
    Please make sure the code you run does what you expect it to do.
"""

import argparse
from pprint import pprint
import requests

print(
    "**DISCLAIMER:** Please note that this code is for educational purposes only. "
    "It is not intended to be run directly in production. "
    "This is provided on a best effort basis. "
    "Please make sure the code you run does what you expect it to do."
)

def get_group_api_consumption(apikey, group_id, start_date, last_date):
    """
    Getting VT API group consumption between 2 dates (by group ID). Please note that available data includes only the last 60 natural days so your range dates have to be part of the last 60 natural days.
    VT API endpoint reference: https://docs.virustotal.com/reference/group-api-usage
    """

    url = f"https://www.virustotal.com/api/v3/groups/{group_id}/api_usage?start_date={start_date}&end_date={last_date}"
    headers = {"accept": "application/json", "x-apikey": apikey}
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

def main():
    parser = argparse.ArgumentParser(
        description="Getting VT API group consumption between 2 dates."
    )
    parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")
    parser.add_argument(
        "--group_id",
        required=True,
        help="Your VT group ID. Check https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md Requirements.",
    )
    parser.add_argument(
        "--start_date",
        required=True,
        help="Start day (yyyymmdd format).",
    )
    parser.add_argument(
        "--last_date",
        required=True,
        help="Last day (yyyymmdd format).",
    )
    args = parser.parse_args()

    (
        total,
        by_endpoint,
        by_endpoint_and_day,
        by_endpoint_not_consuming,
    ) = get_group_api_consumption(
        args.apikey, args.group_id, args.start_date, args.last_date
    )
    if total > 0:
        print(f"\nTOTAL {args.group_id} group API consumption: {total}")
        print("\nConsumption API endpoint breakdown:")
        pprint(by_endpoint)
        print("\nConsumption API endpoint-day breakdown:")
        pprint(by_endpoint_and_day)
        print("\nNot consuming API endpoint breakdown:")
        pprint(by_endpoint_not_consuming)
    else:
        print(
            f"\nThe {args.group_id} has 0 API consumption between {args.start_date} and {args.last_date}."
        )

if __name__ == "__main__":
    main()
