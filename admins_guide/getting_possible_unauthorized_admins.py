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

def get_possible_unauthorized_admins(apikey, group_id, authorized_admins):
    """
    Getting users objects (administrators) related to a group by group ID.
        Requested users attributes: first_name,last_name,email.
    VT API endpoint reference: https://docs.virustotal.com/reference/get-group-administrators
    """

    unauthorized_admins = []
    url = f"https://www.virustotal.com/api/v3/groups/{group_id}/administrators?attributes=first_name,last_name,email"
    headers = {"accept": "application/json", "x-apikey": apikey}
    while url:
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        res = res.json()
        for el in res["data"]:
            if el["id"] not in authorized_admins:
                unauthorized_admins.append(
                    f"username: {el['id']}, "
                    f"first_name: {el['attributes'].get('first_name', '')}, "
                    f"last_name: {el['attributes'].get('last_name', '')}, "
                    f"email: {el['attributes'].get('email', '')}"
                )
        url = res.get("links", {}).get("next", None)
    return unauthorized_admins

def main():
    parser = argparse.ArgumentParser(
        description="Getting the list of probably not authorized administrators of a group."
    )
    parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")
    parser.add_argument(
        "--group_id",
        required=True,
        help="Your VT group ID. Check https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md Requirements.",
    )
    parser.add_argument(
        "--authorized_admins_ids",
        required=True,
        default=[],
        nargs="+",
        help="List of already authorized administrator user ids. Check https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md Requirements.",
    )
    args = parser.parse_args()

    unauthorized_admins = get_possible_unauthorized_admins(
        args.apikey, args.group_id, args.authorized_admins_ids
    )
    if unauthorized_admins:
        print(
            f"\nThere are {len(unauthorized_admins)} possible anomalies (users with admin privileges)."
        )
        pprint(unauthorized_admins)
    else:
        print("\nNo anomalies found.")

if __name__ == "__main__":
    main()
