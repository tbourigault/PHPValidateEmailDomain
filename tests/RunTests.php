<?php

echo 'hello';
require_once dirname(__DIR__) . '/vendor/autoload.php';

$logger = new \CDemers\DoHEmailDomainValidator\Psr\Log\Logger();

try {
    if (isset($argv[1])) {
        $email = $argv[1];
        $validator = new \CDemers\DoHEmailDomainValidator\EmailValidator($logger);
        if ($validator->isValid($argv[1])) {
            echo "The email domain is valid.\n";
        } else {
            echo "Invalid email domain.\n";
        }

    } else {
        echo "Usage: {$argv[0]} <email>\n";
    }

} catch (Exception $e) {
    $logger->error("Exception: {$e->getMessage()}");
}

// Use the following command to run this script:
// first generate autoload file : `composer dump-autoload`
// then `php tests/RunTests.php user.name@example.com`
