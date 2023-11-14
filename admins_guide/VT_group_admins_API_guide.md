# VirusTotal group administrators API walkthrough guide

The purpose of this project is to provide examples of the most common use cases that VirusTotal group administrators may find useful, with a focus on the VT API.

### Requirements

Bellow use case code snippets may require some of the following parameters:

* VirusTotal group ID -> check it [here](https://www.virustotal.com/gui/group/{group_id}/users), on the **GROUP PREFERENCES** section, **Group ID** field.
* VirusTotal user ID -> check it [here](https://www.virustotal.com/gui/group/{group_id}/users), on the **Group members** section by clicking on any user to pivot to its **USER PROFILE** where user ID is found near the user avatar. 
* VirusTotal user API key -> check it [here](https://www.virustotal.com/gui/user/{username}/apikey).

Additionally, please note that the API key used for authentication/authorization in the code snippets below is set as an environment variable.

## Use cases
* Group members management
		- [Getting the list of users and service accounts](https://github.com/VirusTotal/vt-use-cases/blob/admins_guide/admins_guide/getting_group_users_and_service_accounts.py)
	* Users management
		- [Adding new user to the VT group](https://github.com/VirusTotal/vt-use-cases/blob/admins_guide/admins_guide/adding_users_to_group.py)
		- [Removing user from the VT group](https://github.com/VirusTotal/vt-use-cases/blob/admins_guide/admins_guide/remove_users_from_group.py)
		- [Managing users privileges](https://github.com/VirusTotal/vt-use-cases/blob/admins_guide/admins_guide/managing_users_privileges.py)
		- [Managing users API allowance](https://github.com/VirusTotal/vt-use-cases/blob/admins_guide/admins_guide/managing_users_api_allowance.py)

* Consumption
	* VirusTotal Enterprise features consumption
		- [Getting current month group overall enterprise consumption](https://github.com/VirusTotal/vt-use-cases/blob/admins_guide/admins_guide/group_enterprise_current_month_consumption.py)
		- [Users individual consumption](https://github.com/VirusTotal/vt-use-cases/blob/admins_guide/admins_guide/user_enterprise_current_month_consumption.py)
	* API consumption
		- [Getting groups overall consumption](https://github.com/VirusTotal/vt-use-cases/blob/admins_guide/admins_guide/group_api_consumption.py)
		- [Getting users individual consumption](https://github.com/VirusTotal/vt-use-cases/blob/admins_guide/admins_guide/user_api_consumption.py)
