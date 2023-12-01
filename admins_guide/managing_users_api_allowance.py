"""
**DISCLAIMER:**
    Please note that this code is for educational purposes only.
    It is not intended to be run directly in production.
    This is provided on a best effort basis.
    Please make sure the code you run does what you expect it to do.
"""

import argparse
import requests

print(
    "**DISCLAIMER:** Please note that this code is for educational purposes only. "
    "It is not intended to be run directly in production. "
    "This is provided on a best effort basis. "
    "Please make sure the code you run does what you expect it to do."
)

def update_api_cap(apikey, user_id, daily_limit):
    """
    Update user API cap (by its user ID).
    VT API endpoint reference: https://docs.virustotal.com/reference/patch-user-id
    """

    url = f"https://www.virustotal.com/api/v3/users/{user_id}"
    headers = {
        "accept": "text/plain",
        "x-apikey": apikey,
        "content-type": "application/json",
    }
    payload = {
        "data": {
            "type": "user",
            "attributes": {
                "quotas": {"api_requests_daily": {"allowed": int(daily_limit)}}
            },
        }
    }

    res = requests.patch(url, json=payload, headers=headers)
    res.raise_for_status()
    print(f"\nAPI daily cap updated successfully for user {user_id}.")

def main():
    parser = argparse.ArgumentParser(description="Updating users API daily cap.")
    parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")
    parser.add_argument(
        "--daily_limit",
        required=True,
        help="New users API requests allowance",
    )
    parser.add_argument(
        "--users_ids",
        required=True,
        default=[],
        nargs="+",
        help="List of user ids you want to remove from your group. Check https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md Requirements.",
    )
    args = parser.parse_args()

    for user_id in args.users_ids:
        update_api_cap(args.apikey, user_id, args.daily_limit)

if __name__ == "__main__":
    main()
