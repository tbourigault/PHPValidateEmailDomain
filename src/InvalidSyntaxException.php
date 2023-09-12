<?php

declare(strict_types=1);

namespace CDemers\DoHEmailDomainValidator;

use Throwable;
use Exception;

class InvalidSyntaxException extends Exception
{
    public function __construct($email = '', $code = 0, Throwable $previous = null)
    {
        parent::__construct(sprintf('«%s» is not a valid email address.', $email), $code, $previous);
    }
}
