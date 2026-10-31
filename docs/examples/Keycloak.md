# Configure LimeSurvey login with Keycloak

Using this plugin Keycloak can be used to login into LimeSurvey.

## Register a new App in Azure AD

Create a new client with secret on Keycloak  
The plugin configuration so far should look like this:

| Option           | Value                                                                |
|------------------|----------------------------------------------------------------------|
| Client ID        | limesurvey                                                           |
| Client Secret    | your_beloved_secret                                |
| Authorize URL    | https://auth.ulysseus.eu/realms/master/protocol/openid-connect/auth  |
| Scopes           | email, profile                                                       |
| Access Token URL | https://auth.ulysseus.eu/realms/master/protocol/openid-connect/token |
| Access Token URL | https://auth.ulysseus.eu/realms/master/protocol/openid-connect/token |

## Configure User Details

With the retrieved access token LimeSurvey can then fetch the user details.
This will return the user profile in a flat JSON object for which the following keys
can then be configured for the plugin:


| Option                               | Value                                                                 |
|--------------------------------------|-----------------------------------------------------------------------|
| User Details URL                     | https://auth.ulysseus.eu/realms/master/protocol/openid-connect/userinfo |
| Key for username in user details     | given_name.first_letter+family_name.lower_case                        |
| Key for e-mail in user details       | mail                                                                  |
| Key for display name in user details | given_name.capitalize+family_name.upper_case                        |

We have coded few templating functions to make your user name and display name more customizable, you're free to extend it.

## Map Keycloak roles to LimeSurvey user roles

LimeSurvey reads the roles from the **user info** response, not from the access token. Check what your
realm actually returns in the Keycloak admin console under *Clients &rarr; your client &rarr; Client scopes &rarr;
Evaluate &rarr; User info* tab, or with:

```bash
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://auth.example.com/realms/YOUR_REALM/protocol/openid-connect/userinfo | jq
```

Keycloak keeps roles in nested objects, so the key is a dotted JSON path:

| Roles you want                                   | Key for roles in user detail                  |
|--------------------------------------------------|-----------------------------------------------|
| Client roles of client `limesurvey`              | `resource_access.limesurvey.roles`            |
| Realm roles                                      | `realm_access.roles`                          |
| Flat claim added by your own mapper              | `ls_roles`                                    |
| Client whose name contains a dot                 | `resource_access['sondages.pro'].roles`       |
| A claim whose own name contains a dot            | `resource.access.roles` or `[resource.access].roles` |

A key is matched literally first, so a claim genuinely named `resource.access` wins over reading the
same text as two nesting levels. Brackets make that explicit and are optional; quotes inside them are
optional too, which matters because the setting lives in an admin text field that may escape them.

Client roles are usually the right choice: they keep the role list limited to the roles you created for
LimeSurvey, instead of pulling in every realm role such as `offline_access` or `uma_authorization`.

The role names in that list are matched against **LimeSurvey user roles** (permission templates), which
you manage under *Security &amp; permissions &rarr; User roles*. Names that do not match are skipped silently,
so keep the Keycloak role names identical to the LimeSurvey role names, or use
*Allow you to remove specific string on the roles returnned* to strip a prefix such as `LS_`.

Roles are applied when the user is created. Tick *Update roles at each log in* to refresh them on every
login, which removes roles the user no longer has in Keycloak, but also wipes any role granted by hand
in LimeSurvey. Tick *Need a minimum one role* to refuse login for users without any role.
