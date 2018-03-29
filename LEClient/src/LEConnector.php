<?php

/**
 * LetsEncrypt Connector class, containing the functions necessary to sign with JSON Web Key and Key ID, and perform GET, POST and HEAD requests.
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
class LEConnector
{
	public $baseURL;
	public $accountKeysDir;
	
	private $nonce;
	
	public $keyChange;
	public $newAccount;
    public $newNonce;
	public $newOrder;
	public $revokeCert;
	
	public $accountURL;
	public $accountDeactivated = false;
	
	private $log;
	
    /**
     * Initiates the LetsEncrypt Connector class.
     * 
     * @param int 		$log			The level of logging. Defaults to no logging. LOG_OFF, LOG_STATUS, LOG_DEBUG accepted.
     * @param string	$baseURL 		The LetsEncrypt server URL to make requests to.
     * @param string	$accountKeysDir The directory in which the account keys are stored.
     */
	public function __construct($log, $baseURL, $accountKeysDir)
	{
		$this->baseURL = $baseURL;
		$this->accountKeysDir = $accountKeysDir;
		$this->log = $log;
		$this->getLEDirectory();
		$this->getNewNonce();
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
		if(strpos($this->head($this->newNonce)['header'], "204 No Content") == false) throw new \RuntimeException('No new nonce.');
	}
	
    /**
     * Makes a Curl request.
     * 
     * @param string	$method	The HTTP method to use. Accepting GET, POST and HEAD requests.
     * @param string 	$URL 	The URL or partial URL to make the request to. If it is partial, the baseURL will be prepended.
     * @param object 	$data  	The body to attach to a POST request. Expected as a JSON encoded string.
     * 
     * @return array 	Returns an array with the keys 'request', 'header' and 'body'.
     */
	private function request($method, $URL, $data = null)
	{
		if($this->accountDeactivated) throw new \RuntimeException('The account was deactivated. No further requests can be made.');
		
		$headers = array('Accept: application/json', 'Content-Type: application/jose+json');
		$requestURL = preg_match('~^http~', $URL) ? $URL : $this->baseURL . $URL;
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, $requestURL);
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_HEADER, true);

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
				throw new \RuntimeException('HTTP request ' . $method . ' not supported.');
				break;
        }
        $response = curl_exec($handle);

        if(curl_errno($handle)) {
            throw new \RuntimeException('Curl: ' . curl_error($handle));
        }

        $header_size = curl_getinfo($handle, CURLINFO_HEADER_SIZE);

        $header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);
		$jsonbody = json_decode($body, true);
		$jsonresponse = array('request' => $method . ' ' . $requestURL, 'header' => $header, 'body' => $jsonbody === null ? $body : $jsonbody);
		if($this->log >= LECLient::LOG_DEBUG) LEFunctions::log($jsonresponse);
		
		if(	(($method == 'POST' OR $method == 'GET') AND strpos($header, "200 OK") === false AND strpos($header, "201 Created") === false) OR 
			($method == 'HEAD' AND strpos($header, "204 No Content") === false))
		{
			throw new \RuntimeException('Invalid response, header: ' . $header);
		}
		
		if(preg_match('~Replay\-Nonce: (\S+)~i', $header, $matches)) 
		{
			$this->nonce = trim($matches[1]);
		}
		else
		{
			if($method == 'POST') $this->getNewNonce(); // Not expecting a new nonce with GET and HEAD requests.
		}
        
        return $jsonresponse;
	}
	
    /**
     * Makes a GET request.
     * 
     * @param string	$url 	The URL or partial URL to make the request to. If it is partial, the baseURL will be prepended.
     * 
     * @return array 	Returns an array with the keys 'request', 'header' and 'body'.
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
     * @return array 	Returns an array with the keys 'request', 'header' and 'body'.
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
     * @return array	Returns an array with the keys 'request', 'header' and 'body'.
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
     * @param string 	$privateKeyFile The private key to sign the request with. Defaults to 'private.pem'. (optional)
     * @param string 	$privateKeyDir  The directory to get the private key from. Default to the account keys directory given in the constructor. (optional)
     * 
     * @return string	Returns a JSON encoded string containing the signature.
     */
	public function signRequestJWK($payload, $url, $privateKeyFile = 'private.pem', $privateKeyDir = '')
    {
		if($privateKeyDir == '') $privateKeyDir = $this->accountKeysDir;
		$privateKey = openssl_pkey_get_private(file_get_contents($privateKeyDir . $privateKeyFile));
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
     * @param string 	$privateKeyFile The private key to sign the request with. Defaults to 'private.pem'. (optional)
     * @param string 	$privateKeyDir  The directory to get the private key from. Default to the account keys directory given in the constructor. (optional)
     * 
     * @return string	Returns a JSON encoded string containing the signature.
     */
	public function signRequestKid($payload, $kid, $url, $privateKeyFile = 'private.pem', $privateKeyDir = '')
    {
		if($privateKeyDir == '') $privateKeyDir = $this->accountKeysDir;
        $privateKey = openssl_pkey_get_private(file_get_contents($privateKeyDir . $privateKeyFile));
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

?>
