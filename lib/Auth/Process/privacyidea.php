<?php
/**
 * This authentication processing filter allows you to add a second step
 * authentication against privacyIDEA
 *
 * @author Cornelius Kölbel <cornelius.koelbel@netknights.it>
 * @author Jean-Pierre Höhmann <jean-pierre.hoehmann@netknights.it>
 */


class sspmod_privacyidea_Auth_Process_privacyidea extends SimpleSAML_Auth_ProcessingFilter
{
    /**
     * This contains the server configuration
     * @var array
     */
    private $serverconfig;

    /**
     * privacyidea constructor.
     *
     * @param array $config The configuration of this authproc.
     * @param mixed $reserved
     *
     * @throws \SimpleSAML\Error\CriticalConfigurationError in case the configuration is wrong.
     */
    public function __construct(array $config, $reserved)
    {
        assert('array' === gettype($config));

        parent::__construct($config, $reserved);
        $this->serverconfig = $config;
    }

    /**
     * Run the filter.
     *
     * @param array $state
     *
     * @throws \Exception if authentication fails
     */
    public function process(&$state)
    {
        assert('array' === gettype($state));

        SimpleSAML_Logger::info("privacyIDEA Auth Proc Filter: Entering process function");

        // set authenticationMethod
        $state['privacyidea:privacyidea:authenticationMethod'] = "authprocess";

        $this->serverconfig = sspmod_privacyidea_Auth_utils::buildServerconfig(
            $state['privacyidea:serverconfig'],
            $this->serverconfig,
            $state
        );
        $state['privacyidea:privacyidea'] = $this->serverconfig;

        if (sspmod_privacyidea_Auth_utils::privacyIdeaIsDisabled($state, $this->serverconfig)) {
            SimpleSAML_Logger::debug(
                "privacyIDEA: "
                . $this->serverconfig['enabledPath']
                . " -> "
                . $this->serverconfig['enabledKey']
                . " is not set to true -> privacyIDEA is disabled"
            );
            return;
        }


        /**
         * skip privacyIDEA for authenticated users in passive requests
         * if $state["Expire"] is set, the user was already authenticated prior to the present
         * request by the IdP (maybe not with privacyIDEA)
         */
        if (isset($state['isPassive']) && $state['isPassive'] === true) {
            if (isset($state["Expire"]) && $state["Expire"] > time()) {
                SimpleSAML_Logger::debug("privacyIDEA: ignoring passive SAML request for already logged in user");
                return;
            }
            throw new \SimpleSAML\Module\saml\Error\NoPassive('Passive authentication (OTP) not supported.');
        }

        if (
            array_key_exists('SSO', $this->serverconfig)
            && $this->serverconfig['SSO'] === true
            && array_key_exists('core:IdP', $state)
            && array_key_exists('AuthnInstant', $state)
            && array_key_exists('Expire', $state)
            && array_key_exists('Authority', $state)
        ) {
            SimpleSAML_Logger::debug("privacyIDEA: SSO is enabled. Check SSO data from session.");

            $ssoData = \SimpleSAML\Session::getSessionFromRequest()->getData(
                'privacyidea:privacyidea:sso',
                'data'
            );

            if (
                is_array($ssoData)
                && array_key_exists('IdP', $ssoData)
                && $ssoData['IdP'] === $state['core:IdP']
                && array_key_exists('Authority', $ssoData)
                && $ssoData['Authority'] === $state['Authority']
                && array_key_exists('AuthnInstant', $ssoData)
                && $ssoData['AuthnInstant'] === $state['AuthnInstant']
                && array_key_exists('Expire', $ssoData)
                && $ssoData['Expire'] === $state['Expire']
                && array_key_exists('SSOInstant', $ssoData)
                && $ssoData['SSOInstant'] <= time()
            ) {
                SimpleSAML_Logger::debug("privacyIDEA: SSO data is valid. Ignoring SAML request for already logged in user.");
                return;
            }
        }

        if (!$this->serverconfig['privacyideaserver']) {SimpleSAML_Logger::error("privacyIDEA url is not set!");}
        if ($this->maybeTryFirstAuthentication($state)) {return;}
        if ($this->serverconfig['doTriggerChallenge']) {$state = $this->triggerChallenge($state);}

        self::openOtpform($state);
    }

    private function maybeTryFirstAuthentication($state) {
        if (!$this->serverconfig['tryFirstAuthentication']) {
            return false;
        }

        try {
            sspmod_privacyidea_Auth_utils::authenticate(
                $state,
                array('pass' => $this->serverconfig['tryFirstAuthPass'])
            );

            return true;
        } catch (SimpleSAML_Error_Error $error) {
            SimpleSAML_Logger::debug("privacyIDEA: user has token");
            return false;
        }
    }

    private function triggerChallenge($state) {
        assert('array' === gettype($state));

        $parameters = array("user" => $state["Attributes"][$this->serverconfig['uidKey']][0]);
        if (isset($this->serverconfig['realm'])) {
            $parameters["realm"] = $this->serverconfig['realm'];
        } else {
            SimpleSAML_Logger::debug("privacyIDEA: realm not set in config. Letting privacyIDEA server decide.");
        }

        $authToken = sspmod_privacyidea_Auth_utils::fetchAuthToken($this->serverconfig);
        $body = sspmod_privacyidea_Auth_utils::curl(
            $parameters,
            array("authorization:" . $authToken),
            $this->serverconfig,
            "/validate/triggerchallenge",
            "POST");
        return sspmod_privacyidea_Auth_utils::checkTokenType($state, $body);
    }

    private static function openOtpform($state) {
        assert('array' === gettype($state));

        SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is enabled, so we use 2FA");
        $id = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
        $url = SimpleSAML_Module::getModuleURL('privacyidea/otpform.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
    }

    public static function handleLogout() {
        SimpleSAML_Logger::debug("privacyIDEA: handle logout. Remove SSO data.");

        /*
         * This method is static and called after login without providing state
         * and we can't implement separate SSO for different IdP, SP etc.
         * So we delete single SSO data.
         */
        \SimpleSAML\Session::getSessionFromRequest()->deleteData('privacyidea:privacyidea:sso', 'data');
    }
}
