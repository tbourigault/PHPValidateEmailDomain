<?php

declare(strict_types=1);

namespace CDemers\DoHEmailDomainValidator;

use Throwable;
use Exception;

class UnableToVerifyException extends Exception
{
    public function __construct($domain = '', $code = 0, Throwable $previous = null)
    {
        // phpcs:ignore
        parent::__construct(sprintf("The DNS queries to all servers failed while validating domain of email: «%s». Not sure what's happening, but it's likely a problem on our side.", $domain), $code, $previous);
    }
}
