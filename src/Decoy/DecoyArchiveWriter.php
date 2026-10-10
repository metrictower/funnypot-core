<?php

declare(strict_types=1);

namespace Funnypot\Core\Decoy;

/**
 * Minimal, dependency-free archive writers for the decoy outer layer: a store-method zip and a
 * POSIX ustar. Needs only crc32() and pack(), so it works on hosts without ext-zip or phar.
 *
 * Members are [name, bytes, mtime]. Names must be short ASCII (the builder only passes sanitized
 * names), so no UTF-8 flag, zip64 or long-name extensions are needed. Output is a pure function of
 * the members: no clock, no randomness.
 */
final class DecoyArchiveWriter
{
    private const TAR_RECORD = 10240;

    /**
     * @param list<array{0:string,1:string,2:int}> $members
     */
    public static function zipStore(array $members): string
    {
        $out = '';
        $central = '';
        foreach ($members as [$name, $data, $mtime]) {
            [$time, $date] = self::dosDateTime($mtime);
            $crc = crc32($data);
            $size = strlen($data);
            $offset = strlen($out);

            $out .= pack('VvvvvvVVVvv', 0x04034b50, 20, 0, 0, $time, $date, $crc, $size, $size, strlen($name), 0)
                . $name . $data;

            // Version made by 3.0 on Unix (Info-ZIP style), external attrs carry -rw-r--r--.
            $central .= pack('VvvvvvvVVVvvvvvVV', 0x02014b50, 0x031e, 20, 0, 0, $time, $date, $crc, $size, $size,
                strlen($name), 0, 0, 0, 0, (0100644 << 16), $offset) . $name;
        }
        $count = count($members);

        return $out . $central
            . pack('VvvvvVVv', 0x06054b50, 0, 0, $count, $count, strlen($central), strlen($out), 0);
    }

    /**
     * @param list<array{0:string,1:string,2:int}> $members
     */
    public static function ustar(array $members): string
    {
        $out = '';
        foreach ($members as [$name, $data, $mtime]) {
            $out .= self::ustarHeader($name, strlen($data), $mtime) . $data;
            $pad = (512 - strlen($data) % 512) % 512;
            $out .= str_repeat("\0", $pad);
        }
        $out .= str_repeat("\0", 1024);
        // Pad to a full record like GNU tar / bsdtar defaults.
        $rem = strlen($out) % self::TAR_RECORD;

        return $rem === 0 ? $out : $out . str_repeat("\0", self::TAR_RECORD - $rem);
    }

    private static function ustarHeader(string $name, int $size, int $mtime): string
    {
        $h = str_pad($name, 100, "\0")
            . sprintf('%07o', 0644) . "\0"
            . sprintf('%07o', 1000) . "\0"
            . sprintf('%07o', 1000) . "\0"
            . sprintf('%011o', $size) . "\0"
            . sprintf('%011o', $mtime) . "\0"
            . '        '                       // checksum placeholder (8 spaces)
            . '0'                              // regular file
            . str_repeat("\0", 100)            // linkname
            . "ustar\0" . '00'
            . str_pad('deploy', 32, "\0")
            . str_pad('deploy', 32, "\0")
            . sprintf('%07o', 0) . "\0"
            . sprintf('%07o', 0) . "\0"
            . str_repeat("\0", 155);
        $h = str_pad($h, 512, "\0");

        $sum = 0;
        for ($i = 0; $i < 512; $i++) {
            $sum += ord($h[$i]);
        }

        return substr_replace($h, sprintf('%06o', $sum) . "\0 ", 148, 8);
    }

    /**
     * @return array{0:int,1:int} [dos time, dos date]
     */
    private static function dosDateTime(int $ts): array
    {
        $y = (int) gmdate('Y', $ts);
        if ($y < 1980) {
            $ts = 315532800;
            $y = 1980;
        }
        $time = ((int) gmdate('G', $ts) << 11) | ((int) gmdate('i', $ts) << 5) | intdiv((int) gmdate('s', $ts), 2);
        $date = (($y - 1980) << 9) | ((int) gmdate('n', $ts) << 5) | (int) gmdate('j', $ts);

        return [$time, $date];
    }
}
