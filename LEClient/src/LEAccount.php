<?php

/**
 * LetsEncrypt Account class, containing the functions and data associated with a LetsEncrypt account.
 *
 * PHP version 7.1.0
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
 * @version    1.1.0
 * @link       https://github.com/yourivw/LEClient
 * @since      Class available since Release 1.0.0
 */
class LEAccount
{
	private $connector;
	private $accountKeysDir;
	
	public $id;
	public $key;
	public $contact;
	public $agreement;
	public $initialIp;
	public $createdAt;
	public $status;
	
	private $log;
	
    /**
     * Initiates the LetsEncrypt Account class.
     * 
     * @param LEConnector	$connector 		The LetsEncrypt Connector instance to use for HTTP requests.
     * @param int 			$log 			The level of logging. Defaults to no logging. LOG_OFF, LOG_STATUS, LOG_DEBUG accepted.
     * @param array 		$email	 		The array of strings containing e-mail addresses. Only used when creating a new account.
     * @param string 		$accountKeysDir The directory in which the account keys are stored. Is a subdir inside $keysDir.
     */
	public function __construct($connector, $log, $email, $accountKeysDir)
	{
		$this->connector = $connector;
		$this->accountKeysDir = $accountKeysDir;
		$this->log = $log;
		
		if(!file_exists($this->accountKeysDir . 'private.pem') OR !file_exists($this->accountKeysDir . 'public.pem')) 
		{
			if($this->log >= LECLient::LOG_STATUS) LEFunctions::log('No account found, attempting to create account.', 'function LEAccount __construct');
			LEFunctions::RSAgenerateKeys($this->accountKeysDir);
			$this->connector->accountURL = $this->createLEAccount($email);
		}
		else
		{
			$this->connector->accountURL = $this->getLEAccount();
		}
		if($this->connector->accountURL == false) throw new \RuntimeException('Account not found or deactivated.');
		$this->getLEAccountData();
	}
	
    /**
     * Creates a new LetsEncrypt account.
     * 
     * @param array 	$email 	The array of strings containing e-mail addresses.
     * 
     * @return object	Returns the new account URL when the account was successfully created, false if not.
     */
	private function createLEAccount($email)
	{
		$contact = array_map(function($addr) { return empty($addr) ? '' : (strpos($addr, 'mailto') === false ? 'mailto:' . $addr : $addr); }, $email);
		
		$sign = $this->connector->signRequestJWK(array('contact' => $contact, 'termsOfServiceAgreed' => true), $this->connector->newAccount);
		$post = $this->connector->post($this->connector->newAccount, $sign);
		if(strpos($post['header'], "201 Created") !== false)
		{
			if(preg_match('~Location: (\S+)~i', $post['header'], $matches)) return trim($matches[1]);
		}
		return false;
	}
	
    /**
     * Gets the LetsEncrypt account URL associated with the stored account keys.
     * 
     * @return object	Returns the account URL if it is found, or false when none is found.	
     */
	private function getLEAccount()
	{
		$sign = $this->connector->signRequestJWK(array('onlyReturnExisting' => true), $this->connector->newAccount);
		$post = $this->connector->post($this->connector->newAccount, $sign);
		
		if(strpos($post['header'], "200 OK") !== false)
		{
			if(preg_match('~Location: (\S+)~i', $post['header'], $matches)) return trim($matches[1]);
		}
		return false;
	}
	
    /**
     * Gets the LetsEncrypt account data from the account URL.
     */
	private function getLEAccountData()
	{
		$sign = $this->connector->signRequestKid(array('' => ''), $this->connector->accountURL, $this->connector->accountURL);
		$post = $this->connector->post($this->connector->accountURL, $sign);
		if(strpos($post['header'], "200 OK") !== false)
		{
			$this->id = $post['body']['id'];
			$this->key = $post['body']['key'];
			$this->contact = $post['body']['contact'];
			$this->agreement = $post['body']['agreement'];
			$this->initialIp = $post['body']['initialIp'];
			$this->createdAt = $post['body']['createdAt'];
			$this->status = $post['body']['status'];
		}
		else
		{
			throw new \RuntimeException('Account data cannot be found.');
		}
	}
	
    /**
     * Updates account data. Now just supporting new contact information.
     * 
     * @param array 	$email	The array of strings containing e-mail adresses.
     * 
     * @return boolean	Returns true if the update is successful, false if not.
     */
	public function updateAccount($email)
	{
		$contact = array_map(function($addr) { return empty($addr) ? '' : (strpos($addr, 'mailto') === false ? 'mailto:' . $addr : $addr); }, $email);
		
		$sign = $this->connector->signRequestKid(array('contact' => $contact), $this->connector->accountURL, $this->connector->accountURL);
		$post = $this->connector->post($this->connector->accountURL, $sign);
		if(strpos($post['header'], "200 OK") !== false)
		{
			$this->id = $post['body']['id'];
			$this->key = $post['body']['key'];
			$this->contact = $post['body']['contact'];
			$this->agreement = $post['body']['agreement'];
			$this->initialIp = $post['body']['initialIp'];
			$this->createdAt = $post['body']['createdAt'];
			$this->status = $post['body']['status'];
			if($this->log >= LECLient::LOG_STATUS) LEFunctions::log('Account data updated.', 'function updateAccount');
			return true;
		}
		else
		{
			return false;
		}
	}
	
    /**
     * Creates new RSA account keys and updates the keys with LetsEncrypt.
     * 
     * @return boolean	Returns true if the update is successful, false if not.
     */
	public function changeAccountKeys()
	{
		LEFunctions::RSAgenerateKeys($this->accountKeysDir, 'newPrivate.pem', 'newPublic.pem');
		$privateKey = openssl_pkey_get_private(file_get_contents($this->accountKeysDir . 'newPrivate.pem'));
		$details = openssl_pkey_get_details($privateKey);
		
		$innerPayload = array('account' => $this->accountURL, 'newKey' => array(
			"kty" => "RSA",
			"n" => LEFunctions::Base64UrlSafeEncode($details["rsa"]["n"]),
			"e" => LEFunctions::Base64UrlSafeEncode($details["rsa"]["e"])
		));
		$outerPayload = $this->connector->signRequestJWK($innerPayload, $this->connector->keyChange, 'newPrivate.pem');
		$sign = $this->connector->signRequestKid($outerPayload, $this->connector->accountURL, $this->connector->keyChange);
		$post = $this->connector->post($this->connector->keyChange, $sign);
		if(strpos($post['header'], "200 OK") !== false)
		{
			$this->getLEAccountData();
			
			unlink($this->accountKeysDir . 'private.pem');
			unlink($this->accountKeysDir . 'public.pem');
			rename($this->accountKeysDir . 'newPrivate.pem', $this->accountKeysDir . 'private.pem');
			rename($this->accountKeysDir . 'newPublic.pem', $this->accountKeysDir . 'public.pem');
			
			if($this->log >= LECLient::LOG_STATUS) LEFunctions::log('Account keys changed.', 'function changeAccountKey');
			return true;
		}
		else
		{
			return false;
		}
	}
	
    /**
     * Deactivates the LetsEncrypt account.
     * 
     * @return boolean	Returns true if the deactivation is successful, false if not.
     */
	public function deactivateAccount()
	{
		$sign = $this->connector->signRequestKid(array('status' => 'deactivated'), $this->connector->accountURL, $this->connector->accountURL);
		$post = $this->connector->post($this->connector->accountURL, $sign);
		if(strpos($post['header'], "200 OK") !== false)
		{
			$this->connector->accountDeactivated = true;
			if($this->log >= LECLient::LOG_STATUS) LEFunctions::log('Account deactivated.', 'function deactivateAccount');
		}
		else
		{
			return false;
		}
	}
}

?>