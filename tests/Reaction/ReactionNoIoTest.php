<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Reaction;

use PHPUnit\Framework\TestCase;

/**
 * A static gate: no file under src/Reaction/ may reach any I/O, process, network, environment, dynamic
 * callable or header/redirect sink. A reaction is pure synthesis from a bounded value plus code-owned
 * pools; if that ever stops being true, this bites at the token level (comments/docblocks are ignored,
 * so the invariant may still be described in prose).
 */
final class ReactionNoIoTest extends TestCase
{
    /** Forbidden function-call names (T_STRING immediately followed by '('). */
    private const FORBIDDEN_CALLS = [
        'file_get_contents', 'file_put_contents', 'fopen', 'fwrite', 'fread', 'is_file', 'file_exists',
        'glob', 'scandir', 'opendir', 'readfile', 'exec', 'system', 'passthru', 'shell_exec', 'proc_open',
        'popen', 'fsockopen', 'stream_socket_client', 'stream_socket_server', 'gethostbyname',
        'dns_get_record', 'getenv', 'putenv', 'call_user_func', 'call_user_func_array', 'eval',
        'assert', 'header', 'setcookie', 'setrawcookie', 'usleep', 'sleep', 'mt_rand', 'rand',
        'random_bytes', 'random_int', 'curl_init', 'curl_exec',
    ];

    /** Forbidden language constructs (by token id). */
    private const FORBIDDEN_TOKENS = [T_REQUIRE, T_REQUIRE_ONCE, T_INCLUDE, T_INCLUDE_ONCE, T_EVAL];

    public function test_reaction_namespace_performs_no_io(): void
    {
        $dir = dirname(__DIR__, 2) . '/src/Reaction';
        $files = glob($dir . '/*.php');
        self::assertNotEmpty($files, 'src/Reaction must contain files');

        foreach ($files as $file) {
            $tokens = token_get_all((string) file_get_contents($file));
            $count = count($tokens);
            for ($i = 0; $i < $count; $i++) {
                $tok = $tokens[$i];
                if (!is_array($tok)) {
                    continue;
                }
                [$id, $text] = $tok;

                if (in_array($id, self::FORBIDDEN_TOKENS, true)) {
                    self::fail("Forbidden I/O construct '{$text}' in " . basename($file));
                }

                if ($id === T_STRING && in_array(strtolower($text), self::FORBIDDEN_CALLS, true)) {
                    // Only flag a genuine call: the next significant token is '('.
                    $j = $i + 1;
                    while ($j < $count && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                        $j++;
                    }
                    if ($j < $count && $tokens[$j] === '(') {
                        self::fail("Forbidden call '{$text}(' in " . basename($file));
                    }
                }

                if ($id === T_VARIABLE && in_array($text, ['$_GET', '$_POST', '$_SERVER', '$_ENV', '$_REQUEST', '$_COOKIE'], true)) {
                    self::fail("Forbidden superglobal '{$text}' in " . basename($file));
                }
            }
        }
    }
}
