<?php

namespace LEClient;

use Exception;
use LEClient\Exceptions\LEFunctionsException;

/**
 * LetsEncrypt Functions class, supplying the LetsEncrypt Client with supportive functions.
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
class LEFunctions
{
    /**
     * Generates a new RSA keypair and saves both keys to a new file.
     *
     * @param string	$directory		The directory in which to store the new keys. If set to null or empty string - privateKeyFile and publicKeyFile will be treated as absolute paths.
     * @param string	$privateKeyFile	The filename for the private key file.
     * @param string	$publicKeyFile  The filename for the public key file.
     * @param string	$keySize 		RSA key size, must be between 2048 and 4096 (default is 4096)
     */
	public static function RSAGenerateKeys($directory, $privateKeyFile = 'private.pem', $publicKeyFile = 'public.pem', $keySize = 4096)
	{
		if ($keySize < 2048 || $keySize > 4096) throw LEFunctionsException::InvalidArgumentException('RSA key size must be between 2048 and 4096.');

		$res = openssl_pkey_new(array(
			"private_key_type" => OPENSSL_KEYTYPE_RSA,
			"private_key_bits" => intval($keySize),
		));

		if ($res === false) {
			$error = "Could not generate key pair! Check your OpenSSL configuration. OpenSSL Error: ".PHP_EOL;
			while($message = openssl_error_string()){
				$error .= $message.PHP_EOL;
			}
			throw LEFunctionsException::GenerateKeypairException($error);
		}

		if(!openssl_pkey_export($res, $privateKey)) {
			$error = "RSA keypair export failed!! Error: ".PHP_EOL;
			while($message = openssl_error_string()){
				$error .= $message.PHP_EOL;
			}
			throw LEFunctionsException::GenerateKeypairException($error);
		}

		$details = openssl_pkey_get_details($res);

		if ($directory !== null && $directory !== '')
		{
			$privateKeyFile = $directory.$privateKeyFile;
			$publicKeyFile = $directory.$publicKeyFile;
		}

		file_put_contents($privateKeyFile, $privateKey);
		file_put_contents($publicKeyFile, $details['key']);

		openssl_pkey_free($res);
	}

    /**
     * Generates a new EC prime256v1 keypair and saves both keys to a new file.
     *
     * @param string	$directory		The directory in which to store the new keys. If set to null or empty string - privateKeyFile and publicKeyFile will be treated as absolute paths.
     * @param string	$privateKeyFile	The filename for the private key file.
     * @param string	$publicKeyFile  The filename for the public key file.
     * @param string	$keysize  		EC key size, possible values are 256 (prime256v1) or 384 (secp384r1), default is 256
     */
	public static function ECGenerateKeys($directory, $privateKeyFile = 'private.pem', $publicKeyFile = 'public.pem', $keySize = 256)
	{
		if (version_compare(PHP_VERSION, '7.1.0') == -1) throw LEFunctionsException::PHPVersionException();

		if ($keySize == 256)
		{
			$res = openssl_pkey_new(array(
					"private_key_type" => OPENSSL_KEYTYPE_EC,
					"curve_name" => "prime256v1",
			));
		}
		elseif ($keySize == 384)
		{
			$res = openssl_pkey_new(array(
					"private_key_type" => OPENSSL_KEYTYPE_EC,
					"curve_name" => "secp384r1",
			));
		}
		else throw LEFunctionsException::InvalidArgumentException('EC key size must be 256 or 384.');


		if(!openssl_pkey_export($res, $privateKey)) throw LEFunctionsException::GenerateKeypairException('EC keypair export failed!');

		$details = openssl_pkey_get_details($res);

		if ($directory !== null && $directory !== '')
		{
			$privateKeyFile = $directory.$privateKeyFile;
			$publicKeyFile = $directory.$publicKeyFile;
		}

		file_put_contents($privateKeyFile, $privateKey);
		file_put_contents($publicKeyFile, $details['key']);

		openssl_pkey_free($res);
	}



    /**
     * Encodes a string input to a base64 encoded string which is URL safe.
     *
     * @param string	$input 	The input string to encode.
     *
     * @return string	Returns a URL safe base64 encoded string.
     */
	public static function Base64UrlSafeEncode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Decodes a string that is URL safe base64 encoded.
     *
     * @param string	$input	The encoded input string to decode.
     *
     * @return string	Returns the decoded input string.
     */
    public static function Base64UrlSafeDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }



    /**
     * Outputs a log message.
     *
     * @param object	$data		The data to print.
     * @param string	$function	The function name to print above. Defaults to the calling function's name from the stacktrace. (optional)
     */
	public static function log($data, $function = '')
	{
		$e = new Exception();
		$trace = $e->getTrace();
		$function = $function == '' ? 'function ' .  $trace[3]['function'] . ' (function ' . $trace[2]['function'] . ')' : $function;
		if (PHP_SAPI == "cli")
		{
			echo '[' . date('d-m-Y H:i:s') . '] ' . $function . ":\n";
			print_r($data);
			echo "\n\n";
		}
		else
		{
			echo '<b>' . date('d-m-Y H:i:s') . ', ' . $function . ':</b><br>';
			print_r($data);
			echo '<br><br>';
		}
	}



    /**
     * Makes a request to the HTTP challenge URL and checks whether the authorization is valid for the given $domain.
     *
     * @param string	$domain 			The domain to check the authorization for.
     * @param string 	$token 				The token (filename) to request.
     * @param string 	$keyAuthorization 	the keyAuthorization (file content) to compare.
     *
     * @return boolean	Returns true if the challenge is valid, false if not.
     */
	public static function checkHTTPChallenge($domain, $token, $keyAuthorization)
	{
		$requestURL = $domain . '/.well-known/acme-challenge/' . $token;
		$handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, $requestURL);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);	
        $response = trim(curl_exec($handle));

		return (!empty($response) && $response == $keyAuthorization);
	}

    /**
     * Checks whether the applicable DNS TXT record is a valid authorization for the given $domain.
     *
     * @param string	$domain 	The domain to check the authorization for.
     * @param string	$DNSDigest	The digest to compare the DNS record to.
     *
     * @return boolean	Returns true if the challenge is valid, false if not.
     */
	public static function checkDNSChallenge($domain, $DNSDigest)
	{
		$requestURL = 'https://dns.google.com/resolve?name=_acme-challenge.' . $domain . '&type=TXT';
		$handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, $requestURL);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_FOLLOWLOCATION, true);
        $response = json_decode(trim(curl_exec($handle)));
		if($response->Status === 0 && isset($response->Answer))
		{
			foreach($response->Answer as $answer) 
			{
				if($answer->type === 16)
				{
					if($answer->data === $DNSDigest) return true;
				}
			}
		}
		return false;
	}

    /**
     * Creates a simple .htaccess file in $directory which denies from all.
     *
     * @param string	$directory	The directory in which to put the .htaccess file.
     */
	public static function createhtaccess($directory)
	{
		$htaccess = '<ifModule mod_authz_core.c>' . "\n"
			. '    Require all denied' . "\n"
			. '</ifModule>' . "\n"
			. '<ifModule !mod_authz_core.c>' . "\n"
			. '    Deny from all' . "\n"
			. '</ifModule>' . "\n";
		file_put_contents($directory . '.htaccess', $htaccess);
	}
}
