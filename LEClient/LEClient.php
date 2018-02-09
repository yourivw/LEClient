<?php

/**
 * Load the dependencies for the LetsEncrypt Client
 */
require_once('src/LEConnector.php');
require_once('src/LEAccount.php');
require_once('src/LEOrder.php');
require_once('src/LEAuthorization.php');
require_once('src/LEFunctions.php');

/**
 * Main LetsEncrypt Client class, works as a framework for the LEConnector, LEAccount, LEOrder and LEAuthorization classes.
 *
 * PHP version 5.2
 *
 * MIT License
 *
 * Copyright (c) 2018 Youri van Weegberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 * @version    1.0.0
 * @link       https://github.com/yourivw/LEClient
 * @since      Class available since Release 1.0.0
 */
class LEClient
{
	private $baseURL = 			'https://acme-v02.api.letsencrypt.org';
	private $stagingBaseURL = 	'https://acme-staging-v02.api.letsencrypt.org';

	private $keysDir;
	private $accountKeysDir;

	private $connector;
	private $account;

	private $log;

	const LOG_OFF = 0;		// Logs no messages or faults, except Runtime Exceptions.
	const LOG_STATUS = 1;	// Logs only messages and faults.
	const LOG_DEBUG = 2;	// Logs messages, faults and raw responses from HTTP requests.

    /**
     * Initiates the LetsEncrypt main client.
     *
     * @param array		$email	 		The array of strings containing e-mail addresses. Only used in this function when creating a new account.
	 * @param boolean	$staging		Set true to use the staging server. Defaults to false, meaning it uses the production server. (optional)
     * @param int 		$log			The level of logging. Defaults to no logging. LOG_OFF, LOG_STATUS, LOG_DEBUG accepted. Defaults to LOG_OFF. (optional)
     * @param string 	$keysDir 		The main directory in which all keys (and certificates), including account keys, are stored. Defaults to 'keys/'. (optional)
     * @param string 	$accountKeysDir The directory in which the account keys are stored. Is a subdir inside $keysDir. Defaults to '__account/'.(optional)
     */
	public function __construct($email, $staging = false, $log = LEClient::LOG_OFF, $keysDir = 'keys/', $accountKeysDir = '__account/')
	{
		if(substr($keysDir, -1) !== '/') $keysDir .= '/';
		if(substr($accountKeysDir, -1) !== '/') $accountKeysDir .= '/';

		$this->log = $log;
		if($staging) $this->baseURL = $this->stagingBaseURL;
		$this->keysDir = $keysDir;
		$this->accountKeysDir = $this->keysDir . $accountKeysDir;
		if(!file_exists($this->keysDir))
		{
			mkdir($this->keysDir, 0777, true);
			LEFunctions::createhtaccess($this->keysDir);
		}
		if(!file_exists($this->accountKeysDir)) mkdir($this->accountKeysDir, 0777, true);
		$this->connector = new LEConnector($this->log, $this->baseURL, $this->accountKeysDir);
		$this->account = new LEAccount($this->connector, $this->log, $email, $this->accountKeysDir);
		if($this->log) LEFunctions::log('LEClient finished constructing', 'function LEClient __construct');
	}


    /**
     * Returns the LetsEncrypt account used in the current client.
	 *
	 * @return LEAccount	The LetsEncrypt Account instance used by the client.
     */
	public function getAccount()
	{
		return $this->account;
	}

    /**
     * Returns a LetsEncrypt order. If an order exists, this one is returned. If not, a new order is created and returned.
     *
     * @param string	$basename	The base name for the order. Preferable the top domain (example.org). Will be the directory in which the keys are stored. Used for the CommonName in the certificate as well.
     * @param array 	$domains 	The array of strings containing the domain names on the certificate.
     * @param string 	$notBefore	A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) at which the certificate becomes valid. Defaults to the moment the order is finalized. (optional)
     * @param string 	$notAfter  	A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) until which the certificate is valid. Defaults to 90 days past the moment the order is finalized. (optional)
     *
     * @return LEOrder	The LetsEncrypt Order instance which is either retrieved or created.
     */
	public function getOrCreateOrder($basename, $domains, $keyType = 'rsa', $notBefore = '', $notAfter = '')
	{
		return new LEOrder($this->connector, $this->log, $this->keysDir, $basename, $domains, $keyType, $notBefore, $notAfter);
	}
}
?>
