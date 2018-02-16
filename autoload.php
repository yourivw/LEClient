<?php

namespace LEClient {

    spl_autoload_register(function ($className) {

        $filePath = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'LEClient' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, $className) .'.php';
        if(file_exists($filePath))
            require $filePath;
    });
}