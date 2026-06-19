<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Support;

/**
 * ConsoleLogger — logs to PHP's error_log() (or stdout via the
 * error_log destination). Convenience for small services that don't
 * have a structured logger yet.
 */
final class ConsoleLogger implements Logger
{
    public function debug(string $msg, array $kv = []): void
    {
        $this->emit('DEBUG', $msg, $kv);
    }

    public function info(string $msg, array $kv = []): void
    {
        $this->emit('INFO', $msg, $kv);
    }

    public function warn(string $msg, array $kv = []): void
    {
        $this->emit('WARN', $msg, $kv);
    }

    public function error(string $msg, array $kv = []): void
    {
        $this->emit('ERROR', $msg, $kv);
    }

    /**
     * @param  array<string, mixed>  $kv
     */
    private function emit(string $level, string $msg, array $kv): void
    {
        $line = '[helios-permissions][' . $level . '] ' . $msg;
        if (!empty($kv)) {
            $line .= ' ' . json_encode($kv, JSON_UNESCAPED_SLASHES);
        }
        // Use stderr (TYPE_STDERR) so it doesn't pollute the response.
        @file_put_contents('php://stderr', $line . "\n");
    }
}
