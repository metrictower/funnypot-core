<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * Exports a nested array as a 100%-literal PHP expression — no objects, closures, or
 * `::class`. Strings are emitted ASCII-only: any byte outside printable ASCII (and the
 * double-quote / backslash / dollar) becomes a fixed two-digit `\xNN` escape, so a
 * regex witness or hex-decoded binary pattern never writes raw control bytes into the
 * committed artifact.
 */
final class PhpArrayExporter
{
    public function export($value, int $indent = 0): string
    {
        if (is_array($value)) {
            return $this->exportArray($value, $indent);
        }

        return $this->exportScalar($value);
    }

    private function exportArray(array $value, int $indent): string
    {
        if ($value === []) {
            return '[]';
        }

        $pad = str_repeat('    ', $indent + 1);
        $close = str_repeat('    ', $indent);
        $isList = $this->isList($value);

        $lines = [];
        foreach ($value as $k => $v) {
            $prefix = $isList ? '' : $this->exportScalar($k) . ' => ';
            $lines[] = $pad . $prefix . $this->export($v, $indent + 1) . ',';
        }

        return "[\n" . implode("\n", $lines) . "\n" . $close . ']';
    }

    private function exportScalar($value): string
    {
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return 'null';
        }
        if (is_float($value)) {
            return var_export($value, true);
        }

        return $this->exportString((string) $value);
    }

    private function exportString(string $s): string
    {
        $out = '"';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            $o = ord($c);
            if ($c === '\\' || $c === '"' || $c === '$') {
                $out .= '\\' . $c;
            } elseif ($o >= 0x20 && $o <= 0x7e) {
                $out .= $c;
            } else {
                $out .= '\\x' . str_pad(dechex($o), 2, '0', STR_PAD_LEFT);
            }
        }

        return $out . '"';
    }

    private function isList(array $a): bool
    {
        $i = 0;
        foreach ($a as $k => $_) {
            if ($k !== $i) {
                return false;
            }
            $i++;
        }

        return true;
    }
}
