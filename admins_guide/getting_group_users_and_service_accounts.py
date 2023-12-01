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

def get_users_or_service_accounts(apikey, group_id, relationship):
    """
    Getting users or service accounts objects related to a group by group ID and 'users' or 'service_accounts' relationship.
        Requested users attributes: first_name,last_name,email.
    VT API endpoint reference: https://docs.virustotal.com/reference/groups-relationships
    """
    users = []
    url = f"https://www.virustotal.com/api/v3/groups/{group_id}/{relationship}?attributes=first_name,last_name,email"
    headers = {"accept": "application/json", "x-apikey": apikey}
    while url:
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        res = res.json()
        for el in res["data"]:
            users.append(
                f"username: {el['id']},"
                f"first_name: {el['attributes'].get('first_name', '')},"
                f"last_name: {el['attributes'].get('last_name', '')},"
                f"email: {el['attributes'].get('email', '')}, type: {el['type']}"
            )
        url = res.get("links", {}).get("next", None)
    return users

def main():
    parser = argparse.ArgumentParser(
        description="Getting the list of users and service accounts of a group."
    )
    parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")
    parser.add_argument(
        "--group_id",
        required=True,
        help="Your VT group ID. Check https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md Requirements.",
    )
    args = parser.parse_args()

    users = get_users_or_service_accounts(args.apikey, args.group_id, "users")
    pprint(users)
    service_accounts = get_users_or_service_accounts(
        args.apikey, args.group_id, "service_accounts"
    )
    pprint(service_accounts)

if __name__ == "__main__":
    main()
