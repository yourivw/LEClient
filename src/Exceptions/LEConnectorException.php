<?php

namespace LEClient\Exceptions;

/**
 * LetsEncrypt Client Connector exception, extends LEException
 *
 * PHP version 5.2.0
 *
 * MIT License
 *
 * Copyright (c) 2020 Youri van Weegberg
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
 * @copyright  2020 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 * @link       https://github.com/yourivw/LEClient
 * @since      Class available since Release 1.2.0
 */
class LEConnectorException extends LEException
{
	public const NONEWNONCEEXCEPTION 			= 0x11;
	public const ACCOUNTDEACTIVATEDEXCEPTION 	= 0x12;
	public const METHODNOTSUPPORTEDEXCEPTION 	= 0x13;
	public const CURLERROREXCEPTION 			= 0x14;
	public const INVALIDRESPONSEEXCEPTION 		= 0x15;
	
	public static function NoNewNonceException()
	{
		return new static('No new nonce.', self::NONEWNONCEEXCEPTION);
	}
	
	public static function AccountDeactivatedException()
	{
		return new static('The account was deactivated. No further requests can be made.', self::ACCOUNTDEACTIVATEDEXCEPTION);
	}
	
	public static function MethodNotSupportedException(string $method)
	{
		return new static(sprintf('HTTP request %s not supported.', $method), self::METHODNOTSUPPORTEDEXCEPTION);
	}
	
	public static function CurlErrorException(string $error)
	{
		return new static(sprintf('Curl error: %s', $error), self::CURLERROREXCEPTION);
	}
	
	public static function InvalidResponseException(array $response)
	{
		$statusCode = array_key_exists('status', $response) ? $response['status'] : 'unknown';
		return new static(sprintf('Invalid response: %s', $statusCode), self::INVALIDRESPONSEEXCEPTION, null, $response);
	}
}
