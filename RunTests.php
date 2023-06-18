<?php

spl_autoload_register(function ($className) {
    $classFile = __DIR__ . '/' . str_replace('\\', '/', $className) . '.php';
    print("Autoloader will attempt to load class \"$className\" from \"$classFile\".\n");
    if (file_exists($classFile)) {
        require $classFile;
    }
});

use Psr\Log\Logger;

require("validateEmailDomainWithDoH.php");

$log = new Psr\Log\Logger();

try {
    if (isset($argv[1])) {
        $email = $argv[1];

        if (validateEmailDomainWithDoH($argv[1], $log)) {
            echo "The email domain is valid.\n";
        } else {
            echo "Invalid email domain.\n";
        }

    } else {
        echo "Usage: {$argv[0]} <email>\n";
    }

} catch (Exception $e) {
    $log->error("Exception: {$e->getMessage()}");
}

// Use the following command to run this script:
// `php RunTests.php user.name@example.com`