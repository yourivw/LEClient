<?php

namespace LEClient;

use LEClient\Exceptions\LEConnectorException;

/**
 * LetsEncrypt Connector class, containing the functions necessary to sign with JSON Web Key and Key ID, and perform GET, POST and HEAD requests.
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
class LEConnector
{
	public $baseURL;
	public $accountKeys;

	private $nonce;

	public $keyChange;
	public $newAccount;
    public $newNonce;
	public $newOrder;
	public $revokeCert;

	public $accountURL;
	public $accountDeactivated = false;

	private $log;
	
	private $sourceIp = false;

    /**
     * Initiates the LetsEncrypt Connector class.
     *
     * @param int 		$log			The level of logging. Defaults to no logging. LOG_OFF, LOG_STATUS, LOG_DEBUG accepted.
     * @param string	$baseURL 		The LetsEncrypt server URL to make requests to.
     * @param array		$accountKeys 	Array containing location of account keys files.
     * @param string    $sourceIp       Optional source IP address.
     */
	public function __construct($log, $baseURL, $accountKeys, $sourceIp = false)
	{
		$this->baseURL = $baseURL;
		$this->accountKeys = $accountKeys;
		$this->log = $log;
		$this->getLEDirectory();
		$this->getNewNonce();
		$this->sourceIp = $sourceIp;
	}

    /**
     * Requests the LetsEncrypt Directory and stores the necessary URLs in this LetsEncrypt Connector instance.
     */
	private function getLEDirectory()
	{
		$req = $this->get('/directory');
		$this->keyChange = $req['body']['keyChange'];
		$this->newAccount = $req['body']['newAccount'];
		$this->newNonce = $req['body']['newNonce'];
		$this->newOrder = $req['body']['newOrder'];
		$this->revokeCert = $req['body']['revokeCert'];
	}

    /**
     * Requests a new nonce from the LetsEncrypt server and stores it in this LetsEncrypt Connector instance.
     */
	private function getNewNonce()
	{
		if($this->head($this->newNonce)['status'] !== 200) throw LEConnectorException::NoNewNonceException();
	}

    /**
     * Makes a Curl request.
     *
     * @param string	$method	The HTTP method to use. Accepting GET, POST and HEAD requests.
     * @param string 	$URL 	The URL or partial URL to make the request to. If it is partial, the baseURL will be prepended.
     * @param object 	$data  	The body to attach to a POST request. Expected as a JSON encoded string.
     *
     * @return array 	Returns an array with the keys 'request', 'header', 'status' and 'body'.
     */
	private function request($method, $URL, $data = null)
	{
		if($this->accountDeactivated) throw LEConnectorException::AccountDeactivatedException();

		$headers = array('Accept: application/json', 'Content-Type: application/jose+json');
		$requestURL = preg_match('~^http~', $URL) ? $URL : $this->baseURL . $URL;
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, $requestURL);
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_HEADER, true);
        if($this->sourceIp !== false) {
            curl_setopt($handle, CURLOPT_INTERFACE, $this->sourceIp);
        }
        
        switch ($method) {
            case 'GET':
                break;
            case 'POST':
                curl_setopt($handle, CURLOPT_POST, true);
                curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
                break;
			case 'HEAD':
				curl_setopt($handle, CURLOPT_CUSTOMREQUEST, 'HEAD');
				curl_setopt($handle, CURLOPT_NOBODY, true);
				break;
			default:
				throw LEConnectorException::MethodNotSupportedException($method);
				break;
        }
        $response = curl_exec($handle);

        if(curl_errno($handle)) {
            throw LEConnectorException::CurlErrorException(curl_error($handle));
        }

        $headerSize = curl_getinfo($handle, CURLINFO_HEADER_SIZE);
        $statusCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);

        $header = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);
		$jsonbody = json_decode($body, true);
		$jsonresponse = array(
           		'request' => $method . ' ' . $requestURL,
            		'header' => $header,
            		'status' => $statusCode,
            		'body' => $jsonbody === null ? $body : $jsonbody,
        	);
		if($this->log instanceof \Psr\Log\LoggerInterface) 
		{
			$this->log->debug($method . ' response received', $jsonresponse);
		}
		elseif($this->log >= LEClient::LOG_DEBUG) LEFunctions::log($jsonresponse);
		
		if(preg_match('~Replay\-Nonce: (\S+)~i', $header, $matches))
		{
			$this->nonce = trim($matches[1]);
		}
		else
		{
			if($method == 'POST') $this->getNewNonce(); // Not expecting a new nonce with GET and HEAD requests.
		}

		if((($method == 'POST' OR $method == 'GET') AND $statusCode !== 200 AND $statusCode !== 201) OR
			($method == 'HEAD' AND $statusCode !== 200))
		{
			throw LEConnectorException::InvalidResponseException($jsonresponse);
		}

        return $jsonresponse;
	}

    /**
     * Makes a GET request.
     *
     * @param string	$url 	The URL or partial URL to make the request to. If it is partial, the baseURL will be prepended.
     *
     * @return array 	Returns an array with the keys 'request', 'header', 'status' and 'body'.
     */
	public function get($url)
	{
		return $this->request('GET', $url);
	}

	/**
     * Makes a POST request.
     *
     * @param string 	$url	The URL or partial URL to make the request to. If it is partial, the baseURL will be prepended.
	 * @param object 	$data	The body to attach to a POST request. Expected as a json string.
     *
     * @return array 	Returns an array with the keys 'request', 'header', 'status' and 'body'.
     */
	public function post($url, $data = null)
	{
		return $this->request('POST', $url, $data);
	}

	/**
     * Makes a HEAD request.
     *
     * @param string 	$url	The URL or partial URL to make the request to. If it is partial, the baseURL will be prepended.
     *
     * @return array	Returns an array with the keys 'request', 'header', 'status' and 'body'.
     */
	public function head($url)
	{
		return $this->request('HEAD', $url);
	}

    /**
     * Generates a JSON Web Key signature to attach to the request.
     *
     * @param array 	$payload		The payload to add to the signature.
     * @param string	$url 			The URL to use in the signature.
     * @param string 	$privateKeyFile The private key to sign the request with. Defaults to 'private.pem'. Defaults to accountKeys[private_key].
     *
     * @return string	Returns a JSON encoded string containing the signature.
     */
	public function signRequestJWK($payload, $url, $privateKeyFile = '')
    {
		if($privateKeyFile == '') $privateKeyFile = $this->accountKeys['private_key'];
		$privateKey = openssl_pkey_get_private(file_get_contents($privateKeyFile));
        $details = openssl_pkey_get_details($privateKey);

        $protected = array(
            "alg" => "RS256",
            "jwk" => array(
                "kty" => "RSA",
                "n" => LEFunctions::Base64UrlSafeEncode($details["rsa"]["n"]),
                "e" => LEFunctions::Base64UrlSafeEncode($details["rsa"]["e"]),
            ),
			"nonce" => $this->nonce,
			"url" => $url
        );

        $payload64 = LEFunctions::Base64UrlSafeEncode(str_replace('\\/', '/', is_array($payload) ? json_encode($payload) : $payload));
        $protected64 = LEFunctions::Base64UrlSafeEncode(json_encode($protected));

        openssl_sign($protected64.'.'.$payload64, $signed, $privateKey, "SHA256");
        $signed64 = LEFunctions::Base64UrlSafeEncode($signed);

        $data = array(
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64
        );

        return json_encode($data);
    }

	/**
     * Generates a Key ID signature to attach to the request.
     *
     * @param array 	$payload		The payload to add to the signature.
	 * @param string	$kid			The Key ID to use in the signature.
     * @param string	$url 			The URL to use in the signature.
     * @param string 	$privateKeyFile The private key to sign the request with. Defaults to 'private.pem'. Defaults to accountKeys[private_key].
     *
     * @return string	Returns a JSON encoded string containing the signature.
     */
	public function signRequestKid($payload, $kid, $url, $privateKeyFile = '')
    {
		if($privateKeyFile == '') $privateKeyFile = $this->accountKeys['private_key'];
        $privateKey = openssl_pkey_get_private(file_get_contents($privateKeyFile));
        $details = openssl_pkey_get_details($privateKey);

        $protected = array(
            "alg" => "RS256",
            "kid" => $kid,
			"nonce" => $this->nonce,
			"url" => $url
        );

        $payload64 = LEFunctions::Base64UrlSafeEncode(str_replace('\\/', '/', is_array($payload) ? json_encode($payload) : $payload));
        $protected64 = LEFunctions::Base64UrlSafeEncode(json_encode($protected));

        openssl_sign($protected64.'.'.$payload64, $signed, $privateKey, "SHA256");
        $signed64 = LEFunctions::Base64UrlSafeEncode($signed);

        $data = array(
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64
        );

        return json_encode($data);
    }
}
