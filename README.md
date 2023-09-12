# Email Domain Validation Function

This repository provides a PHP function to validate the domain of an email address using DNS over HTTPS 
(DoH) service providers.

The function, `isValid()`, validates an email address by sending a DNS query to one or more DoH 
server (with some reputable defaults included) and checking if the domain of the email has an MX record, and if this MX
record is flagged as malware related or not.

## Table of Contents

- [Getting Started](#getting-started)
- [Usage](#usage)
- [How it Works](#how-it-works)
- [References](#references)
- [Contributing](#contributing)

## Getting Started

The function was tested with PHP 8, but it should work with PHP 7. It requires the cURL and JSON PHP extensions to be 
installed and activated. It also uses the PSR-3 LoggerInterface, and so a PSR-3 compliant logger (like Monolog) should 
be given to the function for logging.

## Usage

Here is a simple usage example:

```php
$logger = new \CDemers\DoHEmailDomainValidator\Psr\Log\Logger();
$emailValidator = new \CDemers\DoHEmailDomainValidator\EmailValidator($logger);
try {
    if ($emailValidator->isValid('user.name@example.com', $log)) {
        echo "Valid domain\n";
    } else {
        echo "Invalid domain\n";
    }
} catch (\CDemers\DoHEmailDomainValidator\InvalidSyntaxException $e) {
    echo 'Caught exception: ',  $e->getMessage(), "\n";
} catch (\CDemers\DoHEmailDomainValidator\UnableToVerifyException $e) {
    // You might want to consider the email valid if inconclusive
}
```

The function `isValid()` takes a string as it's first argument, which should be the email address 
that you want to validate, and a PSR LoggerInterface compliant logger as it's second parameter. The function returns 
`true` if the domain of the email is valid, and `false` if it is not valid or if it's considered dangerous by the DoH
server. The function throws an InvalidSyntaxException if the email fails basic syntax validation and an 
UnableToVerifyException if an error occurs while executing the validation and cannot determine if the domain is valid or 
not.

## How it Works

The function works by making a DNS query for the MX record of the email's domain using a DoH service.

The MX (Mail Exchanger) record is a type of resource record in the Domain Name System that specifies a mail server 
responsible for accepting email messages on behalf of a domain.

If one DoH service is not available, it cycles through the list of DoH services until it finds one that is available. If
none of the DoH services are available, it throws an UnableToVerifyException.

Note that this function does not check if the email address is actually in use. It only checks if the domain of
the email address has an MX record.

## Precautions

This function is depending on third-party DoH servers. Because of this, its functionality could be affected by network 
issues, downtime, or changes in these services. Always make sure to handle the possibility that an exception might be 
thrown.

## References

- For more information about DNS over HTTPS, you can refer to the [RFC8484](https://datatracker.ietf.org/doc/html/rfc8484).
- For more information about MX records, you can refer to the [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035) Section 3.3.9.
- For more information about Cloudflare's DoH service, you can read the following Cloudflare blog post: [Introducing DNS Resolver, 1.1.1.1 (not a joke)](https://blog.cloudflare.com/dns-resolver-1-1-1-1/)
- To understand why DoH matters for privacy and security, read this Cloudflare article: [What is DNS-Over-HTTPS and why does it matter?](https://developers.cloudflare.com/fundamentals/dns/dns-over-https)
- Lists of public DNSCrypt and DoH servers: [DNSCrypt/dnscrypt-resolvers](https://github.com/DNSCrypt/dnscrypt-resolvers)
- The Swiss-based Quad9 Foundation: https://www.quad9.net/
- The PSR-3 LoggerInterface: https://www.php-fig.org/psr/psr-3/

## Tests
Use the following command to run this script:
- first generate autoload file : `composer dump-autoload`
- then `php tests/RunTests.php user.name@example.com`

## Contributing

Feel free to submit pull requests to enhance the functionality of the `EmailValidator` class.

## License

MIT License

Copyright (c) 2023 Charle Demers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
