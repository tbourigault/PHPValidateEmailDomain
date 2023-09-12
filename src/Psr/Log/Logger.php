<?php

namespace CDemers\DoHEmailDomainValidator\Psr\Log;

use Psr\Log\LoggerInterface;

class Logger implements LoggerInterface
{
    public function emergency($message, array $context = []): void
    {
        print("[EMERGENCY] $message\n");
    }

    public function alert($message, array $context = []): void
    {
        print("[ALERT] $message\n");
    }

    public function critical($message, array $context = []): void
    {
        print("[CRITICAL] $message\n");
    }

    public function error($message, array $context = []): void
    {
        print("[ERROR] $message\n");
    }

    public function warning($message, array $context = []): void
    {
        print("[WARNING] $message\n");
    }

    public function notice($message, array $context = []): void
    {
        print("[NOTICE] $message\n");
    }

    public function info($message, array $context = []): void
    {
        print("[INFO] $message\n");
    }

    public function debug($message, array $context = []): void
    {
        print("[DEBUG] $message\n");
    }

    public function log($level, $message, array $context = []): void
    {
        print("[{$level}] $message\n");
    }
}
