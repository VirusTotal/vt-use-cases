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

def get_users_without_2fa(apikey, group_id):
    """
    Getting users objects related to a group by group ID, filtering by 2fa_enabled = false.
        Requested users attributes: first_name,last_name,email.
    VT API endpoint reference: https://docs.virustotal.com/reference/groups-relationships
    """

    users = []
    url = f"https://www.virustotal.com/api/v3/groups/{group_id}/users?attributes=first_name,last_name,email&filter=2fa_enabled:false"
    headers = {"accept": "application/json", "x-apikey": apikey}
    while url:
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        res = res.json()
        for el in res["data"]:
            users.append(
                f"username:{el['id']},"
                f"first_name:{el['attributes'].get('first_name','')},"
                f"last_name:{el['attributes'].get('last_name','')},"
                f"email:{el['attributes'].get('email','')}"
            )
        url = res.get("links", {}).get("next", None)
    return users

def main():
    parser = argparse.ArgumentParser(
        description="Getting the list of users of a group without 2FA."
    )
    parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")
    parser.add_argument(
        "--group_id",
        required=True,
        help="Your VT group ID. Check https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md Requirements.",
    )
    args = parser.parse_args()

    users_without_2fs = get_users_without_2fa(args.apikey, args.group_id)
    if users_without_2fs:
        print(f"\nThere are {len(users_without_2fs)} users without 2FA.")
        pprint(users_without_2fs)
    else:
        print("\nNo users without 2FA.")

if __name__ == "__main__":
    main()
