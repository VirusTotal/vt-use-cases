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

def grant_admin_privileges(apikey, group_id, email_addresses):
    """
    Granting admin privileges to a list of users (by their email addresses).
    VT API endpoint reference: https://developers.virustotal.com/reference/post-group-administrators
    """

    url = f"https://www.virustotal.com/api/v3/groups/{group_id}/relationships/administrators"
    headers = {
        "accept": "application/json",
        "x-apikey": apikey,
        "content-type": "application/json",
    }
    payload = {"data": [{"type": "user", "id": e} for e in email_addresses]}
    res = requests.post(url, json=payload, headers=headers)
    res.raise_for_status()
    print("\nAdmin privileges granted successfully.")

def revoke_admin_privileges(apikey, group_id, user_id):
    """
    Revoking admin privileges of a user (by its user ID).
    VT API endpoint reference: https://developers.virustotal.com/reference/delete-user-group-administrator
    """

    url = f"https://www.virustotal.com/api/v3/groups/{group_id}/relationships/administrators/{user_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": apikey,
    }
    res = requests.delete(url, headers=headers)
    res.raise_for_status()
    print(f"\nAdmin privileges revoked successfully for user {user_id}.")

def main():
    parser = argparse.ArgumentParser(
        description="Managing group members admin privileges: granting and revoking admin privileges."
    )
    parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")
    parser.add_argument(
        "--group_id",
        required=True,
        help="Your VT group ID. Check https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md Requirements.",
    )
    parser.add_argument(
        "--grant_email_addresses",
        default=[],
        nargs="+",
        help="List of email addresses of users you want to grant admin privileges to.",
    )
    parser.add_argument(
        "--revoke_users_ids",
        default=[],
        nargs="+",
        help="List of user ids you want to revoke admin privileges from. Check https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md Requirements.",
    )
    args = parser.parse_args()

    if not args.grant_email_addresses and not args.revoke_users_ids:
        raise Exception("one of the following arguments is required: "
    		"--grant_email_addresses or --revoke_users_ids")

    if args.grant_email_addresses:
        grant_admin_privileges(args.apikey, args.group_id, args.grant_email_addresses)
    for user_id in args.revoke_users_ids:
        revoke_admin_privileges(args.apikey, args.group_id, user_id)

if __name__ == "__main__":
    main()
