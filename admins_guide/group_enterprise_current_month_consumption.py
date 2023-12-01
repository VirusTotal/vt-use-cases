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

def get_group_enterprise_current_month_consumption(apikey, user_id):
    """
    Getting current month VT enterprise group consumption by user ID or user API key.
    VT API endpoint reference: https://docs.virustotal.com/reference/get-user-overall-quotas
    """

    url = f"https://www.virustotal.com/api/v3/users/{user_id}/overall_quotas"
    headers = {"accept": "application/json", "x-apikey": apikey}
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
        f"\tSearches {res['data']['intelligence_searches_monthly']['group']['used']}"
        + f"/{res['data']['intelligence_searches_monthly']['group']['allowed']}\n"
        + f"\tDownloads {res['data']['intelligence_downloads_monthly']['group']['used']}"
        + f"/{res['data']['intelligence_downloads_monthly']['group']['allowed']}\n"
        + f"\tLivehunt rules {res['data']['intelligence_hunting_rules']['group']['used']}"
        + f"/{res['data']['intelligence_hunting_rules']['group']['allowed']}\n"
        + f"\tRetrohunt {res['data']['intelligence_retrohunt_jobs_monthly']['group']['used']}"
        + f"/{res['data']['intelligence_retrohunt_jobs_monthly']['group']['allowed']}\n"
        + f"\tDiff {res['data']['intelligence_vtdiff_creation_monthly']['group']['used']}"
        + f"/{res['data']['intelligence_vtdiff_creation_monthly']['group']['allowed']}\n"
        + f"\tPrivate scanning {res['data']['private_scans_monthly']['group']['used']}"
        + f"/{res['data']['private_scans_monthly']['group']['allowed']}\n"
    )
    return sumarry, res

def main():
    parser = argparse.ArgumentParser(
        description="Getting current month VT enterprise group consumption."
    )
    parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")
    parser.add_argument(
        "--user_id",
        required=True,
        help="Your user ID. Check https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/VT_group_admins_API_guide.md Requirements.",
    )
    args = parser.parse_args()

    summary, breakdown = get_group_enterprise_current_month_consumption(
        args.apikey, args.user_id
    )
    print("\nGroup Enterprise consumption summary:")
    print(summary)
    print("\nGroup Enterprise consumption breakdown:")
    pprint(breakdown)

if __name__ == "__main__":
    main()
