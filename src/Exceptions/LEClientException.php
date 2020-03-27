<?php

namespace LEClient\Exceptions;

/**
 * LetsEncrypt Client exception, extends LEException
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
class LEClientException extends LEException
{
	public const INVALIDARGUMENTEXCEPTION 	= 0x01;
	public const INVALIDDIRECTORYEXCEPTION 	= 0x02;
	
	public static function InvalidArgumentException(string $message)
	{
		return new static($message, self::INVALIDARGUMENTEXCEPTION);
	}
	
	public static function InvalidDirectoryException(string $directory)
	{
		return new static(sprintf('%s directory not found.', $directory), self::INVALIDDIRECTORYEXCEPTION);
	}
}
