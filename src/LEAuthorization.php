<?php

namespace LEClient;

/**
 * LetsEncrypt Authorization class, getting LetsEncrypt authorization data associated with a LetsEncrypt Order instance.
 *
 * PHP version 5.2.0
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
 * @link       https://github.com/yourivw/LEClient
 * @since      Class available since Release 1.0.0
 */
class LEAuthorization
{
	private $connector;

	public $authorizationURL;
	public $identifier;
	public $status;
	public $expires;
	public $challenges;

	private $log;

    /**
     * Initiates the LetsEncrypt Authorization class. Child of a LetsEncrypt Order instance.
     *
     * @param LEConnector	$connector			The LetsEncrypt Connector instance to use for HTTP requests.
     * @param int 			$log 				The level of logging. Defaults to no logging. LOG_OFF, LOG_STATUS, LOG_DEBUG accepted.
     * @param string 		$authorizationURL 	The URL of the authorization, given by a LetsEncrypt order request.
     */
	public function __construct($connector, $log, $authorizationURL)
	{
		$this->connector = $connector;
		$this->log = $log;
		$this->authorizationURL = $authorizationURL;

		$get = $this->connector->get($this->authorizationURL);
		if(strpos($get['header'], "200 OK") !== false)
		{
			$this->identifier = $get['body']['identifier'];
			$this->status = $get['body']['status'];
			$this->expires = $get['body']['expires'];
			$this->challenges = $get['body']['challenges'];
		}
		else
		{
			if($this->log instanceof \Psr\Log\LoggerInterface) 
			{
				$this->log->info('Cannot find authorization \'' . $authorizationURL . '\'.');
			}
			elseif($this->log >= LECLient::LOG_STATUS) LEFunctions::log('Cannot find authorization \'' . $authorizationURL . '\'.', 'function LEAuthorization __construct');
		}
	}

    /**
     * Updates the data associated with the current LetsEncrypt Authorization instance.
     */

	public function updateData()
	{
		$get = $this->connector->get($this->authorizationURL);
		if(strpos($get['header'], "200 OK") !== false)
		{
			$this->identifier = $get['body']['identifier'];
			$this->status = $get['body']['status'];
			$this->expires = $get['body']['expires'];
			$this->challenges = $get['body']['challenges'];
		}
		else
		{
			if($this->log instanceof \Psr\Log\LoggerInterface) 
			{
				$this->log->info('Cannot find authorization \'' . $this->authorizationURL . '\'.');
			}
			elseif($this->log >= LECLient::LOG_STATUS) LEFunctions::log('Cannot find authorization \'' . $this->authorizationURL . '\'.', 'function updateData');
		}
	}

    /**
     * Gets the challenge of the given $type for this LetsEncrypt Authorization instance. Throws a Runtime Exception if the given $type is not found in this
	 * LetsEncrypt Authorization instance.
     *
     * @param int	$type 	The type of verification. Supporting LEOrder::CHALLENGE_TYPE_HTTP and LEOrder::CHALLENGE_TYPE_DNS.
     *
     * @return array	Returns an array with the challenge of the requested $type.
     */
	public function getChallenge($type)
	{
		foreach($this->challenges as $challenge)
		{
			if($challenge['type'] == $type) return $challenge;
		}
		throw new \RuntimeException('No challenge found for type \'' . $type . '\' and identifier \'' . $this->identifier['value'] . '\'.');
	}
}
