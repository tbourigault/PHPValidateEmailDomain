<?php
namespace Psr\Log;

class Logger implements LoggerInterface {
    public function emergency($message, array $context = []) {
        print("[EMERGENCY] $message\n");
    }

    public function alert($message, array $context = []) {
        print("[ALERT] $message\n");
    }

    public function critical($message, array $context = []) {
        print("[CRITICAL] $message\n");
    }

    public function error($message, array $context = []) {
        print("[ERROR] $message\n");
    }

    public function warning($message, array $context = []) {
        print("[WARNING] $message\n");
    }

    public function notice($message, array $context = []) {
        print("[NOTICE] $message\n");
    }

    public function info($message, array $context = []) {
        print("[INFO] $message\n");
    }

    public function debug($message, array $context = []) {
        print("[DEBUG] $message\n");
    }
}