<?php
/**
 * This authentication processing filter allows you to add a second step
 * authentication against privacyIDEA
 *
 * @author Cornelius Kölbel <cornelius.koelbel@netknights.it>
 */



class sspmod_privacyidea_Auth_Process_privacyidea extends SimpleSAML_Auth_ProcessingFilter
{
    /**
     * The URL of the privacyIDEA system
     *
     * @var string
     */
    private $privacyIDEA_URL;

    /**
     * Check if the hostname matches the name in the certificate
     * @var boolean
     */

    private $sslverifyhost;

    /**
     * Check if the certificate is valid, signed by a trusted CA
     * @var boolean
     */
    private $sslverifypeer;

    /**
     * The realm where the user is located in.
     * @var string
     */
    private $realm;

	/**
	 * uidKey
	 * We need to know in which key in "Attributes" the UID is stored.
	 */
	private $uidKey;

	/**
	 * enabledPath
	 * If a different authproc should be able to turn on or off privacyIDEA, the path to the key be entered here.
	 */
	private $enabledPath;

	/**
	 * enabledKey
	 * If it's true, we will do 2FA.
	 */
	private $enabledKey;

	/**
	 * The username for the service account
	 * @var String
	 */
	private $serviceAccount;

	/**
	 * The password for the service account
	 * @var String
	 */
	private $servicePass;

    /**
     * Per se we do not need an attributemap, since all attributes are
     * usually set by the authsource
     */

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
        SimpleSAML_Logger::info("Create the Auth Proc Filter privacyidea");
        parent::__construct($config, $reserved);
        $cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:privacyidea');
        $this->privacyIDEA_URL = $cfg->getString('privacyideaserver', '');
        $this->sslverifyhost = $cfg->getBoolean('sslverifyhost', null);
        $this->sslverifypeer = $cfg->getBoolean('sslverifypeer', null);
        $this->realm = $cfg->getString('realm', '');
        $this->uidKey = $cfg->getString('uidKey', '');
        $this->enabledPath = $cfg->getString('enabledPath', '');
        $this->enabledKey = $cfg->getString('enabledKey', '');
        $this->serviceAccount = $cfg->getString('serviceAccount', '');
	    $this->servicePass = $cfg->getString('servicePass', '');
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
	    SimpleSAML_Logger::info("privacyIDEA Auth Proc Filter: Entering process function");

	    /**
	     * If a configuration is not set in privacyidea:tokenEnrollment,
	     * We are using the config from privacyidea:serverconfig.
	     */

	    if ($this->privacyIDEA_URL === '') {
		    $this->privacyIDEA_URL = $state['privacyidea:serverconfig']['privacyIDEA_URL'];
	    }
	    if ($this->sslverifyhost === null) {
		    $this->sslverifyhost = $state['privacyidea:serverconfig']['sslverifyhost'];
	    }
	    if ($this->sslverifypeer === null) {
		    $this->sslverifypeer = $state['privacyidea:serverconfig']['sslverifypeer'];
	    }
	    if ($this->uidKey === '') {
		    $this->uidKey = $state['privacyidea:serverconfig']['uidKey'];
	    }
	    if ($this->enabledPath === '') {
		    $this->enabledPath = $state['privacyidea:serverconfig']['enabledPath'];
	    }
	    if ($this->enabledKey === '') {
		    $this->enabledKey = $state['privacyidea:serverconfig']['enabledKey'];
	    }
	    if ($this->serviceAccount === '') {
		    $this->serviceAccount = $state['privacyidea:serverconfig']['serviceAccount'];
	    }
	    if ($this->servicePass === '') {
		    $this->servicePass = $state['privacyidea:serverconfig']['servicePass'];
	    }

    	$state['privacyidea:privacyidea'] = array(
    		'privacyIDEA_URL' => $this->privacyIDEA_URL,
		    'sslverifyhost' => $this->sslverifyhost,
		    'sslverifypeer' => $this->sslverifypeer,
		    'realm' => $this->realm,
		    'uidKey' => $this->uidKey,
	    );

    	if (isset($state['privacyidea:serverconfig']['enabledPath'])) {
		    $this->enabledPath = $state['privacyidea:serverconfig']['enabledPath'];
		    $this->enabledKey = $state['privacyidea:serverconfig']['enabledKey'];
	    }

    	if(isset($state[$this->enabledPath][$this->enabledKey][0])) {
    		$piEnabled = $state[$this->enabledPath][$this->enabledKey][0];
	    } else {
    		$piEnabled = True;
	    }

		if ($this->privacyIDEA_URL === '') {
			$piEnabled = False;
			SimpleSAML_Logger::error("privacyIDEA url is not set!");
		}

		if($piEnabled) {
			SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is enabled, so we use 2FA");
			$id  = SimpleSAML_Auth_State::saveState( $state, 'privacyidea:privacyidea:init' );
			$url = SimpleSAML_Module::getModuleURL( 'privacyidea/otpform.php' );
			SimpleSAML_Utilities::redirectTrustedURL( $url, array( 'StateId' => $id ) );
		} else {
			SimpleSAML_Logger::debug("privacyIDEA: " . $this->enabledPath . " -> " . $this->enabledKey . " is not set to true -> privacyIDEA is disabled");
		}
    }

    /**
     * Perform 2FA authentication given the current state and an OTP from a token managed by privacyIDEA
     * The otp is sent to the privacyidea_url.
     *
     * @param array $state The state array in the "privacyidea:privacyidea:init" stage.
     * @param string $otp A one time password generated by a yubikey.
     * @return boolean True if authentication succeeded and the key belongs to the user, false otherwise.
     *
     * @throws \InvalidArgumentException if the state array is not in a valid stage or the given OTP has incorrect
     * length.
     */

    public static function authenticate(array &$state, $otp)
    {

    	if (isset($state['privacyidea:serverconfig'])) {
		    $cfg = $state['privacyidea:serverconfig'];
	    } else {
		    $cfg = $state['privacyidea:privacyidea'];
	    }

        SimpleSAML_Logger::info("privacyIDEA Auth Proc Filter: running authenticate");
	    $curl_instance = curl_init();
	    $params = array(
		    "user" => $state["Attributes"][$cfg['uidKey']][0],
		    "pass" => $otp,
		    "realm"=> $cfg['realm'],
	    );
	    SimpleSAML_Logger::debug("privacyIDEA: UID = " . $state["Attributes"][$cfg['uidKey']][0]);

	    $url = $cfg['privacyIDEA_URL'] . "/validate/samlcheck";

	    curl_setopt($curl_instance, CURLOPT_URL, $url);
	    SimpleSAML_Logger::debug("privacyIDEA: URL = " . $url);
	    curl_setopt($curl_instance, CURLOPT_HEADER, TRUE);
	    curl_setopt($curl_instance, CURLOPT_RETURNTRANSFER, TRUE);
	    curl_setopt($curl_instance, CURLOPT_USERAGENT, "simpleSAMLphp");
	    // Add POST params
	    curl_setopt($curl_instance, CURLOPT_POST, 3);
	    curl_setopt($curl_instance, CURLOPT_POSTFIELDS, $params);

	    if ($cfg['sslverifyhost']) {
		    curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 2);
	    } else {
		    curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 0);
	    }
	    if ($cfg['sslverifypeer']) {
		    curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 2);
	    } else {
		    curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 0);
	    }
	    if(!$response = curl_exec($curl_instance)) {
	        throw new SimpleSAML_Error_BadRequest("privacyIDEA: Bad request to PI server: " . curl_error($curl_instance));
        };
	    SimpleSAML_Logger::debug("privacyIDEA: \n\n\n" . $response . "\n\n\n");
	    $header_size = curl_getinfo($curl_instance, CURLINFO_HEADER_SIZE);
	    $body = json_decode(substr($response, $header_size));
	    try {
	        $result = $body->result;
	        $status = $result->status;
	        $value = $result->value->auth;
        } catch (Exception $e) {
	        throw new SimpleSAML_Error_BadRequest( "privacyIDEA: We were not able to read the response from the PI server");
        }

        if ($status !== True) {
            throw new SimpleSAML_Error_BadRequest("Valid JSON Response, but some internal error occured in PI server");
        } else {
            if ($value !== True){
                SimpleSAML_Logger::debug("privacyIDEA: Wrong user pass");
                return False;
            } else {
	            SimpleSAML_Logger::debug("privacyIDEA: User authenticated successfully");
                return True;
            }
        }


    }
}
