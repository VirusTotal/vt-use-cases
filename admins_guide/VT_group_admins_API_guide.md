# VirusTotal group administrators API walkthrough guide

The purpose of this project is to provide examples of the most common use cases that VirusTotal group administrators may find useful, with a focus on the VT API.

## Requirements

Bellow use case code snippets may require some of the following parameters:

* VirusTotal group ID -> check it on the [landing page](https://www.virustotal.com/gui/home/search) -> your name at the top right corner -> **VT enterprise group** option -> **GROUP PREFERENCES** section -> **Group ID** field.
* VirusTotal user ID -> check it on the [landing page](https://www.virustotal.com/gui/home/search) -> your name at the top right corner -> **VT enterprise group** option -> **Group members** section -> and by clicking on any user to pivot to its **USER PROFILE** where user ID is near the user avatar.
* VirusTotal service account ID -> check it on the [landing page](https://www.virustotal.com/gui/home/search) -> your name at the top right corner -> **VT enterprise group** option -> **Service accounts** section.
* VirusTotal user API key -> check it on the [landing page](https://www.virustotal.com/gui/home/search) -> your name at the top right corner -> **API key** option -> **API Key** field.

Additionally, please note that the API key used for authentication/authorization in the code snippets below is set as an environment variable.


## Use cases
* <a name="group-members-management">Group members management
	* Getting group members
		- [Getting the list of users and service accounts](https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/getting_group_users_and_service_accounts.py)
		- [Getting the list of users with 2FA not enabled]()
	* <a name="users-management">Users management
		- [Adding new user to the VT group](https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/adding_users_to_group.py)
		- [Removing user from the VT group](https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/remove_users_from_group.py)
		- [Managing user privileges](https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/managing_users_privileges.py)
		- [Managing user API allowance](https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/managing_users_api_allowance.py)

* <a name="consumption">Consumption
	* <a name="virustotal-enterprise-features-consumption">VirusTotal enterprise features consumption
		- [Getting current month group overall enterprise consumption](https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/group_enterprise_current_month_consumption.py)
		- [Getting users individual enterprise consumption](https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/user_enterprise_current_month_consumption.py)
	* <a name="api-consumption">VirusTotal API consumption
		- [Getting group overall API consumption](https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/group_api_consumption.py)
		- [Getting users individual API consumption](https://github.com/VirusTotal/vt-use-cases/blob/main/admins_guide/user_api_consumption.py)