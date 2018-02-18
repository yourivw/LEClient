<?php

/**
 * LetsEncrypt Functions class, supplying the LetsEncrypt Client with supportive functions.
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
class LEFunctions
{
    /**
     * Generates a new RSA keypair and saves both keys to a new file.
     *
     * @param string	$directory		The directory in which to store the new keys.
     * @param string	$privateKeyFile	The filename for the private key file.
     * @param string	$publicKeyFile  The filename for the public key file.
     */
	public function RSAGenerateKeys($directory, $privateKeyFile = 'private.pem', $publicKeyFile = 'public.pem')
	{
		$res = openssl_pkey_new(array(
			"private_key_type" => OPENSSL_KEYTYPE_RSA,
			"private_key_bits" => 4096,
		));

		if(!openssl_pkey_export($res, $privateKey)) throw new \RuntimeException("RSA keypair export failed!");

		$details = openssl_pkey_get_details($res);

		file_put_contents($directory . $privateKeyFile, $privateKey);
		file_put_contents($directory . $publicKeyFile, $details['key']);

		openssl_pkey_free($res);
	}



    /**
     * Generates a new EC prime256v1 keypair and saves both keys to a new file.
     *
     * @param string	$directory		The directory in which to store the new keys.
     * @param string	$privateKeyFile	The filename for the private key file.
     * @param string	$publicKeyFile  The filename for the public key file.
     */
	public function ECGenerateKeys($directory, $privateKeyFile = 'private.pem', $publicKeyFile = 'public.pem')
	{
	   if (version_compare(PHP_VERSION, '7.1.0') == -1) throw new \RuntimeException("PHP 7.1+ required for EC keys");

		$res = openssl_pkey_new(array(
			"private_key_type" => OPENSSL_KEYTYPE_EC,
			"curve_name" => "prime256v1",
		));

		if(!openssl_pkey_export($res, $privateKey)) throw new \RuntimeException("EC keypair export failed!");

		$details = openssl_pkey_get_details($res);

		file_put_contents($directory . $privateKeyFile, $privateKey);
		file_put_contents($directory . $publicKeyFile, $details['key']);

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
	public function log($data, $function = '')
	{
		$e = new Exception();
		$trace = $e->getTrace();
		$function = $function == '' ? 'function ' .  $trace[3]['function'] . ' (function ' . $trace[2]['function'] . ')' : $function;
		echo '<b>' . date('d-m-Y H:i:s') . ', ' . $function . ':</b><br>';
		print_r($data);
		echo '<br><br>';
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
	public function checkHTTPChallenge($domain, $token, $keyAuthorization)
	{
		$requestURL = $domain . '/.well-known/acme-challenge/' . $token;
		$handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, $requestURL);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_FOLLOWLOCATION, true);
        $response = curl_exec($handle);
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
	public function checkDNSChallenge($domain, $DNSDigest)
	{
		$DNS = '_acme-challenge.' . str_replace('*.', '', $domain);
		$records = dns_get_record($DNS, DNS_TXT);
		foreach($records as $record)
		{
			if($record['host'] == $DNS && $record['type'] == 'TXT' && $record['txt'] == $DNSDigest) return true;
		}
		return false;
	}



    /**
     * Creates a simple .htaccess file in $directory which denies from all.
     *
     * @param string	$directory	The directory in which to put the .htaccess file.
     */
	public function createhtaccess($directory)
	{
		file_put_contents($directory . '.htaccess', "order deny,allow\ndeny from all");
	}
}

?>
