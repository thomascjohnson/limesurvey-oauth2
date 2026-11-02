<?php

/* @version 1.5.0 */

use League\OAuth2\Client\Provider\GenericProvider;
use LimeSurvey\PluginManager\AuthPluginBase;
use LimeSurvey\PluginManager\LimesurveyApi;
use LimeSurvey\PluginManager\PluginEvent;
use LimeSurvey\PluginManager\PluginManager;

// LimeSurvey >= 6 already bundles league/oauth2-client in its own vendor autoload, which is
// registered before any plugin is loaded. Use the plugin's own vendor/ when it exists
// (LimeSurvey < 6, or after running `composer install` in this directory), and fall back to
// the LimeSurvey core autoloader otherwise.
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once(__DIR__ . '/vendor/autoload.php');
} elseif (!class_exists('League\OAuth2\Client\Provider\GenericProvider')) {
    throw new RuntimeException(sprintf(
        'AuthOAuth2 requires the league/oauth2-client library. Run "composer install" in %s, '
        . 'or use LimeSurvey 6 or newer, which ships the library in its own vendor folder.',
        __DIR__
    ));
}


class AuthOAuth2 extends AuthPluginBase
{
    protected const SESSION_STATE_KEY = 'oauth_auth_state';

    /**
     * Transformations that may be appended to a key with a dot, e.g. "given_name.first_letter".
     * A dot otherwise separates nesting levels of a JSON path.
     */
    protected const KEY_MODIFIERS = ['first_letter', 'capitalize', 'upper_case', 'lower_case'];

    /**
     * String values that mean "off" for a switch setting, whatever the admin typed.
     */
    protected const SWITCH_OFF_VALUES = ['0', 'n', 'no', 'off', 'false', 'null', 'none'];

    protected $storage = 'DbStorage';
    protected static $name = 'OAuth2 Authentication';
    protected static $description = 'Enable Single Sign-On using OAuth2';

    protected $resourceData = [];

    /* @var array Check getPluginSettings */
    protected $settings = [];

    public function init(): void
    {
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('newLoginForm');
        $this->subscribe('getGlobalBasePermissions');
    }

    /**
     * @see parent:getPluginSettings
     * @param mixed $getValues
     */
    public function getPluginSettings($getValues = true)
    {
        if (!Permission::model()->hasGlobalPermission('settings', 'read')) {
            throw new CHttpException(403);
        }
        /* Definition and default */
        $fixedPluginSettings = $this->getFixedGlobalSetting();
        $this->settings = [
            'client_id' => [
                'type' => 'string',
                'label' => $this->gT('Client ID'),
                'default' => $this->getGlobalSetting('client_id'),
                'htmlOptions' => [
                    'readonly' => in_array('client_id', $fixedPluginSettings)
                ]
            ],
            'client_secret' => [
                'type' => 'string',
                'label' => $this->gT('Client Secret'),
                'default' => $this->getGlobalSetting('client_secret'),
                'htmlOptions' => [
                    'readonly' => in_array('client_secret', $fixedPluginSettings)
                ]
            ],
            'redirect_uri' => [
                'type' => 'info',
                'label' => $this->gT('Redirect URI'),
                'content' => CHtml::tag(
                    'input',
                    [
                        'type' => 'text',
                        'class' => 'form-control',
                        'readonly' => true,
                        'value' => $this->api->createUrl('admin/authentication/sa/login', []),
                    ]
                ),
            ],
            'authorize_url' => [
                'type' => 'string',
                'label' => $this->gT('Authorize URL'),
                'default' => $this->getGlobalSetting('authorize_url'),
                'htmlOptions' => [
                    'readonly' => in_array('authorize_url', $fixedPluginSettings)
                ]
            ],
            'scopes' => [
                'type' => 'string',
                'label' => $this->gT('Scopes'),
                'help' => $this->gT('Comma-separated list of scopes to use for authorization.'),
                'default' => $this->getGlobalSetting('scopes'),
                'htmlOptions' => [
                    'readonly' => in_array('scopes', $fixedPluginSettings)
                ]
            ],
            'scope_separator' => [
                'type' => 'string',
                'label' => $this->gT('Scopes separator in URL'),
                'help' => $this->gT('Separate scopes in authorization URL.'),
                'default' => $this->getGlobalSetting('scope_separator', ','),
                'htmlOptions' => [
                    'readonly' => in_array('scope_separator', $fixedPluginSettings)
                ]
            ],
            'access_token_url' => [
                'type' => 'string',
                'label' => $this->gT('Access Token URL'),
                'default' => $this->getGlobalSetting('access_token_url', ''),
                'htmlOptions' => [
                    'readonly' => in_array('access_token_url', $fixedPluginSettings)
                ]
            ],
            'resource_owner_details_url' => [
                'type' => 'string',
                'label' => $this->gT('User Details URL'),
                'help' => $this->gT('URL to load the user details from using the retrieved access token.'),
                'default' => $this->getGlobalSetting('resource_owner_details_url', ''),
                'htmlOptions' => [
                    'readonly' => in_array('resource_owner_details_url', $fixedPluginSettings)
                ]
            ],
            'identifier_attribute' => [
                'type' => 'select',
                'label' => $this->gT('Identifier Attribute'),
                'help' => $this->gT('Attribute of the LimeSurvey user to match against.'),
                'options' => [
                    'username' => $this->gT('Username'),
                    'email' => $this->gT('E-Mail'),
                ],
                'default' => $this->getGlobalSetting('identifier_attribute', 'username'),
                'htmlOptions' => [
                    'disabled' => in_array('identifier_attribute', $fixedPluginSettings)
                ],
                'selectOptions' => [
                    'disabled' => in_array('identifier_attribute', $fixedPluginSettings)
                ]
            ],
            'username_key' => [
                'type' => 'string',
                'label' => $this->gT('Key for username in user details'),
                'help' => $this->gT('Key for the username in the user details data. Only required if used as "Identifier Attibute" or if "Create new users" is enabled.'),
                'default' => $this->getGlobalSetting('username_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('username_key', $fixedPluginSettings)
                ]
            ],
            'email_key' => [
                'type' => 'string',
                'label' => $this->gT('Key for e-mail in user details'),
                'help' => $this->gT('Key for the e-mail in the user details data. Only required if used as "Identifier Attibute" or if "Create new users" is enabled.'),
                'default' => $this->getGlobalSetting('email_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('email_key', $fixedPluginSettings)
                ]
            ],
            'display_name_key' => [
                'type' => 'string',
                'label' => $this->gT('Key for display name in user details'),
                'help' => $this->gT('Key for the full name in the user details data. Only required if "Create new users" is enabled.'),
                'default' => $this->getGlobalSetting('display_name_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('display_name_key', $fixedPluginSettings)
                ]
            ],
            'is_default' => [
                'type' => 'checkbox',
                'label' => $this->gT('Use as default login'),
                'help' => sprintf(
                    '%s<br>%s',
                    $this->gT('If enabled instead of showing the LimeSurvey login the user is redirected directly to the OAuth2 login. The default login form can always be accessed via:'),
                    htmlspecialchars($this->api->createUrl('admin/authentication/sa/login', ['authMethod' => 'Authdb']))
                ),
                'default' => $this->getGlobalSetting('is_default', false),
                'htmlOptions' => [
                    'disabled' => in_array('is_default', $fixedPluginSettings)
                ]
            ],
            'autocreate_users' => [
                'type' => 'checkbox',
                'label' => $this->gT('Create new users'),
                'help' => $this->gT('If enabled users that do not exist yet will be created in LimeSurvey after successfull login.'),
                'default' => $this->getGlobalSetting('autocreate_users', false),
                'htmlOptions' => [
                    'disabled' => in_array('autocreate_users', $fixedPluginSettings)
                ]
            ],
            'introduction_text' => [
                'type' => 'string',
                'label' => $this->gT('Introduction to the OAuth login button.'),
                'default' => $this->getGlobalSetting('introduction_text', ''),
                'htmlOptions' => [
                    'placeholder' => $this->gT('Login with Oauth2'),
                    'readonly' => in_array('introduction_text', $fixedPluginSettings)
                ]
            ],
            'button_text' => [
                'type' => 'string',
                'label' => $this->gT('Text on login button.'),
                'default' => $this->getGlobalSetting('button_text', ''),
                'htmlOptions' => [
                    'placeholder' => $this->gT('Login'),
                    'readonly' => in_array('button_text', $fixedPluginSettings)
                ]
            ],
        ];

        if (method_exists(Permissiontemplates::class, 'applyToUser')) {
            $roles = [];
            foreach (Permissiontemplates::model()->findAll() as $role) {
                $roles[$role->ptid] = $role->name;
            }

            $this->settings['autocreate_roles'] = [
                'type' => 'select',
                'label' => $this->gT('Global roles for new users'),
                'help' => $this->gT('Global user roles to be assigned to users that are automatically created.'),
                'options' => $roles,
                'htmlOptions' => [
                    'multiple' => true,
                    'disabled' => in_array('autocreate_roles', $fixedPluginSettings)
                ],
                'default' => $this->getGlobalSetting('autocreate_roles', ''),
                'selectOptions' => [
                    'disabled' => in_array('autocreate_roles', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_key'] = [
                'type' => 'string',
                'label' => $this->gT('Key for roles in user detail'),
                'help' => $this->gT('Path to the user detail attribute that holds the roles. The value must be a list of role names matching existing LimeSurvey user roles. Examples: "roles", "realm_access.roles", "resource_access.myclient.roles". A name that itself contains a dot is matched literally, or can be written in brackets: "[resource.access].roles".'),
                'default' => $this->getGlobalSetting('roles_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('roles_key', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_update'] = [
                'type' => 'checkbox',
                'label' => $this->gT('Update roles at each log in'),
                'help' => $this->gT('Check and update roles each time an user log in.'),
                'default' => $this->getGlobalSetting('roles_update', ''),
                'htmlOptions' => [
                    'disabled' => in_array('roles_update', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_needed'] = [
                'type' => 'checkbox',
                'label' => $this->gT('Need a minimum one role to allow log in or create user.'),
                'help' => $this->gT('If user didn\'t have any roles : disallow log in. Roles name are not checked with existing role.'),
                'default' => $this->getGlobalSetting('roles_needed', ''),
                'htmlOptions' => [
                    'disabled' => in_array('roles_needed', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_removetext'] = [
                'type' => 'string',
                'label' => $this->gT('Allow you to remove specific string on the roles returned'),
                'help' => $this->gT('This string was removed to the roles returned before comparison.'),
                'default' => $this->getGlobalSetting('roles_removetext', ''),
                'htmlOptions' => [
                    'readonly' => in_array('roles_removetext', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_insensitive'] = [
                'type' => 'checkbox',
                'label' => $this->gT('Insensitive comparison for roles'),
                'help' => $this->gT('Do an insensitive comparison before search the roles.'),
                'default' => $this->getGlobalSetting('roles_insensitive', ''),
                'htmlOptions' => [
                    'disabled' => in_array('roles_insensitive', $fixedPluginSettings)
                ]
            ];
        }

        $this->settings['autocreate_permissions'] = [
            'type' => 'json',
            'label' => $this->gT('Global permissions for new users'),
            'help' => sprintf(
                "%s<br><br><strong>%s</strong> %s",
                sprintf(
                    $this->gT('A JSON object describing the default permissions to be assigned to users that are automatically created. The JSON object has the following form: %s'),
                    CHtml::tag('pre', [], "{\n\t\"surveys\": { ... },\n\t\"templates\": {\n\t\t\"create\": false,\n\t\t\"read\": false,\n\t\t\"update\": false,\n\t\t\"delete\": false,\n\t\t\"import\": false,\n\t\t\"export\": false,\n\t},\n\t\"users\": { ... },\n\t...\n}")
                ),
                $this->gT('Note:'),
                $this->gT('an empty object grants no permissions at all. Once a user belongs to any LimeSurvey user role, LimeSurvey answers permission questions from that role and ignores these per-user permissions, so grant the rights on the role instead.')
            ),
            'editorOptions' => array('mode' => 'tree'),
            'default' => $this->getGlobalSetting(
                'autocreate_permissions',
                self::getDefaultPermission()
            ),
            'htmlOptions' => [
                'disabled' => in_array('autocreate_permissions', $fixedPluginSettings)
            ],
        ];
        /* Get current */
        $pluginSettings = parent::getPluginSettings($getValues);
        /* Update current for fixed one */
        if ($getValues) {
            foreach ($fixedPluginSettings as $setting) {
                $pluginSettings[$setting]['current'] = $this->getGlobalSetting($setting);
            }
        }
        /* Remove hidden */
        foreach ($this->getHiddenGlobalSetting() as $setting) {
            unset($pluginSettings[$setting]);
        }
        return $pluginSettings;
    }

    public function newLoginForm()
    {
        $oEvent = $this->getEvent();
        $introductionText = viewHelper::purified(trim($this->getGlobalSetting('introduction_text')));
        if (empty($introductionText)) {
            $introductionText = $this->gT("Login with Oauth2");
        }
        $buttonText = viewHelper::purified(trim($this->getGlobalSetting('button_text')));
        if (empty($buttonText)) {
            $buttonText = $this->gT("Login");
        }
        $aData = [
            'introductionText' => $introductionText,
            'buttonText' => $buttonText,
        ];
        $authContent = $content = $this->renderPartial('admin.authentication.Oauth2LoginButton', $aData, true);
        $allFromsContent = $oEvent->getAllContent();
        foreach ($allFromsContent as $plugin => $content) {
            $oEvent->getContent($plugin)->addContent($authContent, 'prepend');
        }
    }

    /**
     * @throws CHttpException
     */
    public function beforeLogin()
    {
        $request = $this->api->getRequest();
        if ($error = $request->getParam('error')) {
            throw new CHttpException(401, $request->getParam('error_description', $error));
        }

        $provider = new GenericProvider([
            'clientId' => $this->getGlobalSetting('client_id'),
            'clientSecret' => $this->getGlobalSetting('client_secret'),
            'redirectUri' => $this->api->createUrl('admin/authentication/sa/login', []),
            'urlAuthorize' => $this->getGlobalSetting('authorize_url'),
            'urlAccessToken' => $this->getGlobalSetting('access_token_url'),
            'urlResourceOwnerDetails' => $this->getGlobalSetting('resource_owner_details_url'),
            'scopeSeparator' => $this->getGlobalSetting('scope_separator'),
            'scopes' => array_map(
                function ($scope) {
                    return trim($scope);
                },
                explode(',', $this->getGlobalSetting('scopes', ''))
            ),
        ]);

        $code = $request->getParam('code');
        $defaultAuth = $this->isSettingEnabled('is_default') ? self::class : null;
        if (empty($code) && $request->getParam('authMethod', $defaultAuth) !== self::class) {
            return;
        }

        if (empty($code)) {
            $authorizationUrl = $provider->getAuthorizationUrl();
            Yii::app()->session->add(self::SESSION_STATE_KEY, $provider->getState());

            $request->redirect($authorizationUrl);
        }

        $state = $request->getParam('state');
        $safedState = Yii::app()->session->get(self::SESSION_STATE_KEY);
        if ($state !== $safedState) {
            throw new CHttpException(400, $this->gT('Invalid state in OAuth response'));
        }

        Yii::app()->session->remove(self::SESSION_STATE_KEY);

        try {
            $accessToken = $provider->getAccessToken('authorization_code', ['code' => $code]);
        } catch (Throwable $exception) {
            throw new CHttpException(400, $this->gT('Failed to retrieve access token'));
        }

        try {
            $resourceOwner = $provider->getResourceOwner($accessToken);
            $this->resourceData = $resourceOwner->toArray();
        } catch (Throwable $exception) {
            throw new CHttpException(400, $this->gT('Failed to retrieve user details'));
        }

        if ($this->getGlobalSetting('identifier_attribute') === 'email') {
            $identifierKey = $this->getGlobalSetting('email_key');
        } else {
            $identifierKey = $this->getGlobalSetting('username_key');
        }
        $userIdentifier = $this->getTemplatedKey($identifierKey);

        if (empty($userIdentifier)) {
            throw new CHttpException(400, 'User identifier not found or empty');
        }
        $this->setUsername($userIdentifier);
        $this->setAuthPlugin();
    }

    /**
     * @throws CHttpException
     */
    public function newUserSession()
    {
        $userIdentifier = $this->getUserName();
        $identity = $this->getEvent()->get('identity');
        if ($identity->plugin != self::class || $identity->username !== $userIdentifier) {
            return;
        }
        $oIdentityEvent = $this->getEvent();

        if ($this->getGlobalSetting('identifier_attribute') === 'email') {
            $user = $this->api->getUserByEmail($userIdentifier);
        } else {
            $user = $this->api->getUserByName($userIdentifier);
        }

        if (!$user && !$this->isSettingEnabled('autocreate_users')) {
            if ($this->isSettingEnabled('is_default')) {
                /* No way to connect : throw a 403 error (avoid looping) */
                throw new CHttpException(403, gT('Incorrect username and/or password!'));
            } else {
                $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);
                return;
            }
        }
        if ($this->isSettingEnabled('roles_needed') && ($rolesKey = $this->getGlobalSetting('roles_key', ''))) {
            $aRoles = $this->getFromResourceData($rolesKey);
            if (empty($aRoles)) {
                if ($this->isSettingEnabled('is_default')) {
                    /* No way to connect : throw a 403 error (avoid looping) */
                    throw new CHttpException(403, gT('Incorrect username and/or password!'));
                } else {
                    $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);
                    return;
                }
            }
        }
        if (!$user) {
            /* unregister to don't update event */
            $this->unsubscribe('getGlobalBasePermissions');

            $usernameKey = $this->getGlobalSetting('username_key');
            $username = $this->getTemplatedKey($usernameKey);
            $displayNameKey = $this->getGlobalSetting('display_name_key');
            $displayName = $this->getTemplatedKey($displayNameKey, ' ');
            $emailKey = $this->getGlobalSetting('email_key');
            $email = $this->getFromResourceData($emailKey);

            $user = new User();
            $user->parent_id = 0;
            $user->setPassword(createPassword());

            $user->users_name = $username;
            $user->full_name = $displayName;
            $user->email = $email;

            if (!$user->save()) {
                throw new CHttpException(401, $this->gT('Failed to create new user'));
            }
            Yii::app()->db->createCommand()
                ->delete('{{permissions}}', 'uid = :uid', [':uid' => (int) $user->uid]);
            /* Add auth_oauth2 permission if not already exist*/
            self::setOauthPermission($user->uid, true);
            /* Add optional roles */
            if (method_exists(Permissiontemplates::class, 'applyToUser')) {
                $autocreateRoles = $this->getGlobalSetting('autocreate_roles');
                if (!empty($autocreateRoles)) {
                    foreach ($autocreateRoles as $role) {
                        Permissiontemplates::model()->applyToUser($user->uid, $role);
                    }
                }
                $this->setRolesToUser($user->uid);
            }
            $this->setUsername($user->users_name);
            $this->setAuthSuccess($user, $oIdentityEvent);
        } else {
            /* Update roles if needed */
            if ($this->isSettingEnabled('roles_update')) {
                UserInPermissionrole::model()->deleteAll("uid = :uid", [':uid' => $user->uid]);
                $this->setRolesToUser($user->uid);
            }
            /* Check for permission */
            if (!Permission::model()->hasGlobalPermission('auth_oauth', 'read', $user->uid)) {
                /* Check if permission exist : if not create as true, else send error */
                $permissionnExist = Permission::model()->findByAttributes([
                    'entity_id' => 0,
                    'entity' => 'global',
                    'uid' => $user->uid,
                    'permission' => 'auth_oauth'
                ]);
                if (empty($permissionnExist)) {
                    Permission::model()->setGlobalPermission($user->uid, 'auth_oauth');
                } else {
                    if ($this->isSettingEnabled('is_default')) {
                        /* No way to connect : throw a 403 error (avoid looping) */
                        throw new CHttpException(403, gT('Incorrect username and/or password!'));
                    } else {
                        $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);
                        return;
                    }
                }
            }
            $this->setUsername($user->users_name);
            $this->setAuthSuccess($user);
        }
    }

    public function getGlobalBasePermissions(): void
    {
        $this->getEvent()->append('globalBasePermissions', array(
            'auth_oauth' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => "Use OAuth authentication",
                'description' => "Use OAuth authentication",
                'img' => 'fa fa-user-circle-o'
            ),
        ));
    }

    /**
     * @param string $iKey
     * @param string $iSeparator
     * @return string
     */
    public function getTemplatedKey(string $iKey, string $iSeparator = '.'): string
    {
        $rValue = '';
        if (str_contains($iKey, '.') || str_contains($iKey, '+')) {
            $sub_values = array_map(
                function ($sub_key) {
                    $value = $this->getFromResourceData($sub_key);
                    // A template key must yield text: a path to an object or list is a
                    // configuration error, and reporting it beats a join() type error.
                    if (is_array($value) || is_object($value)) {
                        throw new CHttpException(401, $this->gT('User data is missing required attributes to create new user:') . $sub_key);
                    }
                    return $value;
                },
                explode("+", $iKey)
            );

            $rValue = join($iSeparator, $sub_values);
        } else {
            $rValue = $this->getFromResourceData($iKey);
            if (is_array($rValue) || is_object($rValue)) {
                throw new CHttpException(401, $this->gT('User data is missing required attributes to create new user:') . $iKey);
            }
        }
        return (string) $rValue;
    }

    /**
     * @param string $key
     * @return mixed
     */
    private function getFromResourceData(string $key): mixed
    {
        $value = self::resolvePath($this->resourceData, $key);
        if (empty($value)) {
            return [];
        }
        return $value;
    }

    /**
     * Read a value from the user details using a dotted JSON path, so that nested claims can
     * be used. Both shapes work:
     *   "email"                                  -> flat claim
     *   "resource_access.limesurvey.roles"        -> Keycloak client roles
     *   "realm_access.roles"                      -> Keycloak realm roles
     *   "resource_access['some.client'].roles"     -> client IDs that contain a dot
     * An optional trailing modifier (see KEY_MODIFIERS) is applied to the value found.
     *
     * @param array|object|null $data decoded user details
     * @param string $path
     * @return mixed null when the path does not exist
     */
    public static function resolvePath($data, string $path): mixed
    {
        $tokens = self::splitPath($path);
        if (empty($tokens)) {
            return null;
        }

        // A trailing transformation such as "given_name.first_letter". Never popped when it is
        // the only token, so a claim genuinely named "upper_case" still resolves.
        $modifier = null;
        $last = (string) end($tokens);
        if (count($tokens) > 1 && !self::isBracketed($last) && in_array($last, self::KEY_MODIFIERS, true)) {
            $modifier = array_pop($tokens);
        }

        $value = self::lookupTokens($tokens, $data);
        return $modifier === null ? $value : self::applyKeyModifier($value, $modifier);
    }

    /**
     * Walk the tokens down the data tree. At every level the LONGEST literal key wins, so a
     * claim whose own name contains a dot ("resource.access") is preferred over re-reading it
     * as two nesting levels, and a wrong guess surfaces as an error instead of as wrong roles.
     *
     * @param array<int,string> $tokens tokens still to consume, brackets still attached
     * @param array|object|null $node
     * @return mixed null when nothing matches
     */
    private static function lookupTokens(array $tokens, $node): mixed
    {
        if (empty($tokens)) {
            return $node;
        }
        if (!is_array($node) && !is_object($node)) {
            return null;
        }

        // Consecutive plain tokens may be joined into one key; a bracketed token is atomic.
        $longest = 1;
        for ($i = 1; $i < count($tokens); $i++) {
            if (self::isBracketed($tokens[$i])) {
                break;
            }
            $longest = $i + 1;
        }

        for ($length = $longest; $length >= 1; $length--) {
            $slice = array_slice($tokens, 0, $length);
            $key = implode('.', array_map([__CLASS__, 'keyOfToken'], $slice));

            if (is_array($node) && array_key_exists($key, $node)) {
                $found = self::lookupTokens(array_slice($tokens, $length), $node[$key]);
            } elseif (is_object($node) && property_exists($node, $key)) {
                $found = self::lookupTokens(array_slice($tokens, $length), $node->{$key});
            } else {
                continue;
            }

            if ($found !== null) {
                return $found;
            }
        }
        return null;
    }

    /**
     * @param string $token
     * @return bool whether the token was written in brackets and is therefore atomic
     */
    private static function isBracketed(string $token): bool
    {
        return str_starts_with($token, '[');
    }

    /**
     * Strip the brackets and any quotes from a bracketed token; plain tokens pass through.
     *
     * @param string $token
     * @return string
     */
    private static function keyOfToken(string $token): string
    {
        return self::isBracketed($token) ? trim($token, "[]'\" \t") : $token;
    }

    /**
     * Split a path into tokens. Brackets mark a key that contains a dot, quoted or not:
     * "[resource.access].roles", "['sondages.pro'].roles" and "[\"sondages.pro\"].roles"
     * all work. Quotes are optional, which matters because the setting is stored in an
     * admin text field that may escape them.
     *
     * @param string $path
     * @return array<int,string>
     */
    private static function splitPath(string $path): array
    {
        $path = trim($path);
        if ($path === '') {
            return [];
        }
        // Either a bracketed group (kept intact, quotes and all) or a run of plain characters.
        if (!preg_match_all('/\[[^\]]*\]|[^.\[\]]+/', $path, $matches)) {
            return [];
        }
        return $matches[0];
    }

    /**
     * Apply one of the KEY_MODIFIERS transformations to a value.
     *
     * @param mixed $value
     * @param string $modifier
     * @return mixed
     */
    private static function applyKeyModifier($value, string $modifier)
    {
        if (!is_scalar($value)) {
            return $value;
        }
        $value = (string) $value;

        switch ($modifier) {
            case 'first_letter':
                return join('', array_map(
                    function ($spaceSeparatedElements) {
                        return $spaceSeparatedElements === '' ? '' : strtolower($spaceSeparatedElements[0]);
                    },
                    explode(' ', $value)
                ));
            case 'capitalize':
                return ucfirst(strtolower($value));
            case 'upper_case':
                return strtoupper($value);
            case 'lower_case':
                return strtolower($value);
            default:
                return $value;
        }
    }

    /**
     * Normalise the autocreate_permissions setting into a permission array, or null when it is
     * not usable at all.
     *
     * The value reaches us in three shapes: DbStorage json_decodes every stored value, so a saved
     * setting arrives as an array; a value from config.php AuthOAuth2Settings may be an array or a
     * JSON string; and the plugin default is the JSON string from getDefaultPermission(). A JSON
     * object with no entries is a real answer ("grant nothing") and must stay an empty array, while
     * a malformed value must not silently grant anything.
     *
     * @param mixed $value
     * @return array|null null when the value is missing or cannot be interpreted
     */
    public static function normalizePermissionSetting($value): ?array
    {
        if (is_string($value)) {
            $value = trim($value);
            if ($value === '') {
                return null;
            }
            $decoded = json_decode($value, true);
            // A bare string that is not JSON, or a JSON scalar, is not a permission set.
            return is_array($decoded) ? $decoded : null;
        }
        return is_array($value) ? $value : null;
    }

    /**
     * Read a setting that is used as a switch.
     *
     * Values arrive from three places: the settings form (a checkbox posts "1", or nothing at
     * all when unchecked, which LimeSurvey saves as null), config.php AuthOAuth2Settings fixed
     * or default entries, and hand-edited databases. LimeSurvey writes "Y"/"N" for booleans
     * elsewhere, and "N" is truthy in PHP, so an admin who follows that convention in
     * config.php would silently get the switch turned ON. Anything shaped like a refusal is
     * therefore treated as off.
     *
     * @param string $setting
     * @return bool
     */
    private function isSettingEnabled(string $setting): bool
    {
        return self::isSwitchOn($this->getGlobalSetting($setting, false));
    }

    /**
     * @param mixed $value
     * @return bool
     */
    public static function isSwitchOn($value): bool
    {
        if (is_string($value)) {
            $value = trim($value);
            return $value !== '' && !in_array(strtolower($value), self::SWITCH_OFF_VALUES, true);
        }
        if (is_array($value)) {
            return !empty($value);
        }
        return (bool) $value;
    }

    /**
     * get settings according to current DB and fixed config.php
     * @param string $setting
     * @param mixed $default
     * @return mixed
     */
    private function getGlobalSetting($setting, $default = null)
    {
        $AuthOAuth2Settings = App()->getConfig('AuthOAuth2Settings');
        if (isset($AuthOAuth2Settings['fixed'][$setting])) {
            return $AuthOAuth2Settings['fixed'][$setting];
        }
        if (isset($AuthOAuth2Settings[$setting])) {
            return $this->get($setting, null, null, $AuthOAuth2Settings[$setting]);
        }
        return $this->get($setting, null, null, $default);
    }

    /**
     * Get the fixed settings name
     * @return string[]
     */
    private function getFixedGlobalSetting()
    {
        $AuthOAuth2Setting = App()->getConfig('AuthOAuth2Settings');
        if (isset($AuthOAuth2Setting['fixed'])) {
            return array_keys($AuthOAuth2Setting['fixed']);
        }
        return [];
    }

    /**
     * Get the hidden settings name
     * @return string[]
     */
    private function getHiddenGlobalSetting()
    {
        $AuthOAuth2Setting = App()->getConfig('AuthOAuth2Settings');
        if (isset($AuthOAuth2Setting['hidden'])) {
            return $AuthOAuth2Setting['hidden'];
        }
        return [];
    }

     /**
      * Return global default permission
      * @return string
      */
    private static function getDefaultPermission()
    {
        return json_encode([
            'surveys' => [
                'create' => true,
                'read' => false,
                'update' => false,
                'delete' => false,
                'export' => false,
            ],
            'surveysgroups' => [
                'create' => false,
                'read' => true,
                'update' => false,
                'delete' => false,
            ],
            'labelsets' => [
                'create' => false,
                'read' => true,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
            ],
            'templates' => [
                'create' => false,
                'read' => true,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
            ],
            'users' => [
                'create' => false,
                'read' => false,
                'update' => false,
                'delete' => false,
            ],
            'usergroups' => [
                'create' => false,
                'read' => false,
                'update' => false,
                'delete' => false,
            ],
            'settings' => [
                'read' => false,
                'update' => false,
                'import' => false,
            ],
            'participantpanel' => [
                'create' => false,
                'read' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
            ],
            'auth_db' => [
                'read' => false,
            ]
        ]);
    }

    /**
     * Normalise whatever the claim contains into a clean list of role names.
     * A list is the normal case; a single string happens when the Keycloak mapper has
     * "Multivalued" switched off, and a comma separated string when it was aggregated.
     *
     * @param mixed $roles
     * @return array<int,string>
     */
    public static function normalizeRoleList($roles): array
    {
        if (is_string($roles)) {
            $roles = explode(',', $roles);
        } elseif (is_object($roles)) {
            $roles = get_object_vars($roles);
        } elseif (!is_array($roles)) {
            $roles = [$roles];
        }

        $roles = array_map(
            static function ($role) {
                return trim((string) $role);
            },
            $roles
        );

        return array_values(array_filter($roles, static function ($role) {
            return $role !== '';
        }));
    }

    /**
     * Set the roles using current settings
     * @param integer $userId
     */
    private function setRolesToUser($userId)
    {
        if (method_exists(Permissiontemplates::class, 'applyToUser')) {
            $autocreateRoles = $this->getGlobalSetting('autocreate_roles');
            if (!empty($autocreateRoles)) {
                foreach ($autocreateRoles as $role) {
                    Permissiontemplates::model()->applyToUser($userId, $role);
                }
            }
        }
        $rolesKey = $this->getGlobalSetting('roles_key', '');
        if (!empty($rolesKey)) {
            $aRoles = self::normalizeRoleList($this->getFromResourceData($rolesKey));
            if (!empty($aRoles)) {
                $resetPermission = false;
                foreach ($aRoles as $role) {
                    $rolesRemovetext = $this->getGlobalSetting('roles_removetext', '');
                    $role = str_replace($rolesRemovetext, '', $role);
                    $criteria = new CDbCriteria();
                    if ($this->isSettingEnabled('roles_insensitive')) {
                        $criteria->compare('LOWER(name)', strtolower($role), true);
                    } else {
                        $criteria->compare('name', $role, true);
                    }
                    $oRole = Permissiontemplates::model()->find($criteria);
                    if ($oRole) {
                        $resetPermission = true;
                        Permissiontemplates::model()->applyToUser($userId, $oRole->ptid);
                    }
                }
                // Set the auth_oauth global permission to 0 (not used if have roles, but keep it at 0 for roles_needed
                if ($resetPermission) {
                    self::setOauthPermission($userId, false);
                }
            }
        }
    }
    /**
     * Set Oauth permission  : use to create permission with 0 ar read_p or update if exist.
     * @param integer $userId
     * @param boolean $allow permission
     */
    private static function setOauthPermission($userId, $allow = true)
    {
        $oPermission = Permission::model()->find(
            "uid= :uid AND entity = :entity AND permission = :permission",
            array(
                'uid' => $userId,
                'entity' => 'global',
                'permission' => 'auth_oauth',
            )
        );
        if (!$oPermission) {
            $oPermission = new Permission();
            $oPermission->uid = $userId;
            $oPermission->entity = 'global';
            $oPermission->entity_id = 0;
            $oPermission->permission = 'auth_oauth';
        }
        $oPermission->create_p = 0;
        $oPermission->read_p = intval(boolval($allow));
        $oPermission->update_p = 0;
        $oPermission->delete_p = 0;
        $oPermission->import_p = 0;
        $oPermission->export_p = 0;
        $oPermission->save();
    }
}
