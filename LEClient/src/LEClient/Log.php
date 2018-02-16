<?php

namespace LEClient;

/**
 * LetsEncrypt Logger class
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
class Log
{
    const LEVEL_OFF = 0;		// Logs no messages or faults, except Runtime Exceptions.
    const LEVEL_STATUS = 1;	// Logs only messages and faults.
    const LEVEL_DEBUG = 2;    // Logs messages, faults and raw responses from HTTP requests.

    protected $desiredLogLevel = self::LEVEL_OFF;

    public function __construct($desiredLogLevel)
    {
        $this->desiredLogLevel = $desiredLogLevel;
    }

    /**
     * Outputs a log message.
     *
     * @param int   $logLevel   Desired log level
     * @param object|array|string	$data		The data to print.
     * @param string	$function	The function name to print above. Defaults to the calling function's name from the stacktrace. (optional)
     */
    public function add($logLevel, $data, $function = '')
    {
        if($logLevel > $this->desiredLogLevel)
            return; // Desired log level not reached

        $e = new \Exception();
        $trace = $e->getTrace();
        $function = $function == '' ? 'function ' .  $trace[3]['function'] . ' (function ' . $trace[2]['function'] . ')' : $function;
        echo '<b>' . date('d-m-Y H:i:s') . ', ' . $function . ':</b><br>';
        print_r($data);
        echo '<br><br>';
    }
}