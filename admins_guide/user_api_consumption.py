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

def get_group_users(apikey, group_id):
    """
    Getting group users ID list (by group ID).
    VT API endpoint reference: https://developers.virustotal.com/reference/get-group-users
    """

    users = []
    url = f"https://www.virustotal.com/api/v3/groups/{group_id}/relationships/users"
    headers = {"accept": "application/json", "x-apikey": apikey}

    while url:
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        res = res.json()
        users.extend([e["id"] for e in res["data"]])
        url = res.get("links", {}).get("next", None)
    return users

def get_user_api_consumption(apikey, user_id, start_date, last_date):
    """
    Getting VT API user consumption between 2 dates (by user ID). Please note that available data includes only the last 60 natural days so your range dates have to be part of the last 60 natural days.
    VT API endpoint reference: https://developers.virustotal.com/reference/user-api-usage
    """

    url = f"https://www.virustotal.com/api/v3/users/{user_id}/api_usage?start_date={start_date}&end_date={last_date}"
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
    return res

def main():
    parser = argparse.ArgumentParser(
        description="Getting VT API user consumption between 2 dates."
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
    parser.add_argument(
        "--users_ids",
        default=[],
        nargs="+",
        help="List of user ids whose API consumption you want to check. Check https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md Requirements.",
    )
    args = parser.parse_args()

    users_ids = args.users_ids
    if not args.users_ids:
        users_ids = get_group_users(args.apikey, args.group_id)

    for user_id in users_ids:
        print(f"\nUSER: {user_id}")
        pprint(
            get_user_api_consumption(
                args.apikey, user_id, args.start_date, args.last_date
            )
        )

if __name__ == "__main__":
    main()
