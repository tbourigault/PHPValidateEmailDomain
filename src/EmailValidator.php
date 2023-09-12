<?php

declare(strict_types=1);

namespace CDemers\DoHEmailDomainValidator;

use CDemers\DoHEmailDomainValidator\Psr\Log\LoggerInterface;

class EmailValidator {

    private LoggerInterface $logger;
    private ?array $DoHServers;

    /**
     * @param LoggerInterface $logger A logger object to log messages.
     * @param array|null $DoHServers An array of DNS over HTTPS (DoH) servers to use for validation.
     */
    public function __construct(LoggerInterface $logger, array $DoHServers = null)
    {
        $this->logger = $logger;
        $this->DoHServers = $DoHServers;
    }

    /**
     * This function validates the domain of a given email address. It returns true
     * if the email domain is valid, and false if the domain is not valid.  The
     * function will throw exceptions if there is an irrecoverable problem validating
     * the domain.
     *
     * @param string $email The email address for which domain is to be validated.
     * @return bool Returns true if the domain of the email is valid, false otherwise.
     * @throws InvalidSyntaxException If invalid email provided .
     * @throws UnableToVerifyException If unable to determine validity across all servers.
     *
     * Usage example:
     * ```php
     * $logger = new \CDemers\DoHEmailDomainValidator\Psr\Log\Logger();
     * $emailValidator = new CDemers/DoHEmailDomainValidator/EmailValidator($logger);
     * try {
     *     if ($emailValidator->isValid('user.name@example.com')) {
     *        echo "The email domain is valid.\n";
     *    } else {
     *       echo "Invalid email domain.\n";
     *   }
     * } catch (\CDemers\DoHEmailDomainValidator\InvalidSyntaxException $e) {
     *    echo 'Caught exception: ',  $e->getMessage(), "\n";
     * } catch (\CDemers\DoHEmailDomainValidator\UnableToVerifyException $e) {
     *    // You might want to consider the email valid if inconclusive
     * }
     * ```
     */
    public function isValid(string $email): bool
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new InvalidSyntaxException("Invalid email address format: {$email}");
        }

        // We know that the email is well-formed at this point, so we can safely use explode() to extract the domain part
        // of the email address without doing any further validation.
        $domain = explode('@', $email)[1];

        // If one DoH service is not available, it cycles through the list of DoH services until it finds one that is
        // available. If none of the DoH services are available, it throws an exception.
        //
        // In this default list, the first two services are for filtering out domains with bad reputation, the last two
        // services do not filter, but they will only be used if the previous ones are all unavailable.
        $defaultServers = [
        //  'Fake Server To Test' => 'https://example.com/example-query',
            'Quad9 Foundation' => 'https://dns.quad9.net:5053/dns-query',
            'Cloudflare for Teams' => 'https://security.cloudflare-dns.com/dns-query',
            'Cloudflare' => 'https://cloudflare-dns.com/dns-query',
            'Google' => 'https://dns.google/resolve',
        ];

        if ($this->DoHServers === null) {
            $this->DoHServers = $defaultServers;
        }

        foreach ($this->DoHServers as $serverName => $urlPrefix) {
            $url = "$urlPrefix?name={$domain}&type=MX";
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['accept: application/dns-json']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

            $result = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

            curl_close($ch);

            if ($result === false || $httpCode != 200) {
                $this->logger->warning("Failed to query \"{$serverName}\" server while validating domain of email: {$domain}. HTTP status code: {$httpCode}");
                continue;
            }

            $json = json_decode($result);

            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->logger->warning("Failed to decode JSON while validating domain of email: {$domain} using {$serverName} server. JSON error: " . json_last_error_msg());
                continue;
            }

            if ($json->Status == 5) {
                $this->logger->warning("The DNS server \"{$serverName}\" refused to answer while validating domain of email: {$domain} (RCODE 5). Which could mean it was flagged as a malware domain or other such bad reputation activities.");
                return false;
            }

            if ($json->Status !== 0) {
                $this->logger->warning("The DNS server \"{$serverName}\" returned an error (RCODE {$json->Status}) while validating domain of email: {$domain}. DNS query status: \"" . $this->DNSRCodeToString($json->Status) . "\"");
                return false;
            }

            if (!isset($json->Answer) || (isset($json->Answer[0]) && $json->Answer[0]->data == '0.0.0.0')) {
                $this->logger->debug("Domain of email: {$domain} is missing or might be flagged as a malware domain or other such bad reputation activities using \"{$serverName}\" server.");
                return false;
            }

            $this->logger->debug("Successfully validated domain of email: {$domain} using \"{$serverName}\" server.");
            return true;
        }

        // All servers failed...
        throw new UnableToVerifyException($domain);
    }

    // DNS Return Codes Lookup Table
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
    private function DNSRCodeToString(int $rcode): string
    {
        // From RFC 1035 and RFC 6895
        // Ref: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
        $codes = [
            0 => 'No Error',
            1 => 'Format Error: The name server was unable to interpret the query.',
            2 => 'Server Failure: The name server was unable to process this query due to a problem with the name server.',
            3 => 'Name Error: Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.',
            4 => 'Not Implemented: The name server does not support the requested kind of query.',
            5 => 'Refused: The name server refuses to perform the specified operation for policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.',
            6 => 'YXDomain: Name Exists when it should not.',
            7 => 'YXRRSet: RR Set Exists when it should not (a RR Set is a collection of records with the same record type, for example, a collection of A records for a given host name).',
            8 => 'NXRRSet: RR Set that should exist does not (a RR Set is a collection of records with the same record type, for example, a collection of A records for a given host name).',
            9 => 'NotAuth: Server Not Authoritative for zone.',
            10 => 'NotZone: Name not contained in zone.',
            11 => 'DSOTYPENI: DSO-TYPE Not Implemented (a DSO-TYPE is a mechanism for storing and retrieving information other than DNS RR information).',
            16 => 'BADVERS: Bad OPT Version (an OPT Version is a way to indicate that a DNS message is EDNS0-enabled, and EDNS0 is a backwards-compatible extension to DNS).',
            17 => 'BADKEY: Key not recognized (where Key is a key for a DNSSEC-related operation).',
            18 => 'BADTIME: Signature out of time window.',
            19 => 'BADMODE: Bad TKEY Mode (A TKEY is a temporary key used to authenticate messages and to negotiate authenticated keys).',
            20 => 'BADNAME: Duplicate key name.',
            21 => 'BADALG: Algorithm not supported.',
            22 => 'BADTRUNC: Bad Truncation.',
            23 => 'BADCOOKIE: Bad/missing Server Cookie.',
        ];
        if (!isset($codes[$rcode])) {
            return "Unknown or undefined DNS RCODE \"{$rcode}\", refer to IANA DNS Parameters Registry for more information.";
        }
        return $codes[$rcode];
    }
}
