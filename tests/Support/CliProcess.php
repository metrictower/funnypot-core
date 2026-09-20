<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Support;

/** Bounded, PHP 7.3-compatible subprocess runner for local CLI fixtures. */
final class CliProcess
{
    /** @param string[] $args @param array<string,string> $env @return array{int,string,string} */
    public static function run(array $args, string $cwd, array $env = []): array
    {
        $command = (DIRECTORY_SEPARATOR === '/' ? 'exec ' : '')
            . implode(' ', array_map('escapeshellarg', $args));
        $pipes = [];
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes,
            $cwd, $env === [] ? null : array_merge((array) getenv(), $env));
        if (!is_resource($process)) {
            throw new \RuntimeException('CLI fixture could not start');
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = '';
        $err = '';
        $deadline = hrtime(true) + 15000000000;
        $code = -1;
        try {
            do {
                $out .= (string) stream_get_contents($pipes[1], 1048577);
                $err .= (string) stream_get_contents($pipes[2], 1048577);
                if (strlen($out) + strlen($err) > 1048576) {
                    throw new \RuntimeException('CLI fixture exceeded output bound');
                }
                $status = proc_get_status($process);
                if (!$status['running']) {
                    $code = $status['exitcode'];
                    $out .= (string) stream_get_contents($pipes[1], 1048577);
                    $err .= (string) stream_get_contents($pipes[2], 1048577);
                    if (strlen($out) + strlen($err) > 1048576) {
                        throw new \RuntimeException('CLI fixture exceeded output bound');
                    }
                    break;
                }
                if (hrtime(true) >= $deadline) {
                    throw new \RuntimeException('CLI fixture exceeded 15-second wall bound');
                }
                usleep(10000);
            } while (true);
        } finally {
            if ($code < 0 && proc_get_status($process)['running']) {
                proc_terminate($process, 9);
            }
            fclose($pipes[1]);
            fclose($pipes[2]);
            $closed = proc_close($process);
        }

        return [$code >= 0 ? $code : $closed, $out, $err];
    }
}
