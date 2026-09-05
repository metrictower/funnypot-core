<?php

declare(strict_types=1);

namespace Funnypot\Core\Reaction;

use Funnypot\Core\Attack\CannedData;
use Funnypot\Core\Support\SubSeed;

/**
 * Renders one of the five closed reaction families into a ReactionFragment — the code-owned bytes on
 * either side of the SINGLE display slot. Everything here is code-owned and deploy-seeded: the attacker
 * value is NEVER placed into $before/$after (the decorator inserts it, encoded, into the slot), so the
 * fingerprint guard can scan the code-owned halves without ever touching the reflected value.
 *
 * The value selects only a closed bucket (a familiar file name, a shell verb) — never a file to read, a
 * command to run, a URL to fetch, a class, a callable or a template. Every pool string is code-owned
 * and fingerprint-clean by test; any generated digit run goes through SubSeed::reroll so a deploy seed
 * outside the test grid can never mint a denylisted `\b9\d{5}\b` token.
 *
 * PURE: a function of (intent, deploy seed, mode) and the seeded canned generators. No I/O of any kind.
 * 7.3-safe: strpos, substr, preg_match, implode only.
 */
final class ParamReactionRenderer
{
    /**
     * @param string $mode 'html' or 'text' (the decorator derives it from the base Content-Type)
     */
    public function render(ParamIntent $intent, int $deploySeed, string $mode): ?ReactionFragment
    {
        if ($mode !== 'html' && $mode !== 'text') {
            return null;
        }
        $html = $mode === 'html';

        switch ($intent->kind) {
            case ParamIntent::KIND_FILE_READ:
                return $this->fileRead($intent->value, $deploySeed, $html);
            case ParamIntent::KIND_REDIRECT_NOTICE:
                return $this->redirectNotice($deploySeed, $html);
            case ParamIntent::KIND_DEBUG_VIEW:
                return $this->debugView($deploySeed, $html);
            case ParamIntent::KIND_COMMAND_RESULT:
                return $this->commandResult($intent->value, $deploySeed, $html);
            case ParamIntent::KIND_SEARCH_RESULT:
                return $this->searchResult($deploySeed, $html);
            default:
                return null;
        }
    }

    // --- file-read -------------------------------------------------------------------------------

    private function fileRead(string $value, int $seed, bool $html): ReactionFragment
    {
        $content = $this->fileContent($this->fileBucket($value), $seed);

        if ($html) {
            return new ReactionFragment(
                "\n<section class=\"file-preview\"><h2>File contents</h2><p>Requested path: <code>",
                "</code></p><pre>" . $content . "</pre></section>\n",
                true
            );
        }

        return new ReactionFragment("\n# file: ", "\n" . $content, true);
    }

    /** Bucket the requested path by bounded substring tests into one closed content family. */
    private function fileBucket(string $value): string
    {
        $v = strtolower($value);
        if (strpos($v, 'shadow') !== false) {
            return 'shadow';
        }
        if (strpos($v, 'passwd') !== false) {
            return 'passwd';
        }
        if (strpos($v, 'wp-config') !== false) {
            return 'wordpress-config';
        }
        if (strpos($v, '.env') !== false || strpos($v, 'environ') !== false) {
            return 'env';
        }
        if (strpos($v, 'hosts') !== false) {
            return 'hosts';
        }

        return 'generic-file';
    }

    private function fileContent(string $bucket, int $seed): string
    {
        switch ($bucket) {
            case 'passwd':
                return rtrim(CannedData::passwd($seed), "\n") . "\n";
            case 'shadow':
                return rtrim(CannedData::shadow($seed), "\n") . "\n";
            case 'env':
                // /proc/self/environ is NUL-separated on the wire; present it line-wise for display.
                return rtrim(str_replace("\x00", "\n", CannedData::environ($seed)), "\n") . "\n";
            case 'hosts':
                return $this->hostsFile($seed);
            case 'wordpress-config':
                return $this->wpConfig($seed);
            default:
                return $this->genericFile($seed);
        }
    }

    private function hostsFile(int $seed): string
    {
        $host = rtrim(CannedData::hostname($seed), "\n");
        $octet = 1 + SubSeed::index($seed, SubSeed::NS_REACTION, 'hosts|octet', 254);

        return "127.0.0.1\tlocalhost\n"
            . "::1\tlocalhost ip6-localhost ip6-loopback\n"
            . '192.0.2.' . $octet . "\t" . $host . "\n";
    }

    private function wpConfig(int $seed): string
    {
        $db = SubSeed::pick(['wp_db', 'wordpress', 'wpsite', 'blog_db', 'cms_main'], $seed, SubSeed::NS_REACTION, 'wp|db');
        $user = SubSeed::pick(['wp_user', 'wpadmin', 'dbuser', 'www_wp', 'site_admin'], $seed, SubSeed::NS_REACTION, 'wp|user');
        $pass = SubSeed::reroll('wp|pass', static function (string $f) use ($seed): string {
            return SubSeed::chars($seed, SubSeed::NS_REACTION, $f, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789', 16);
        });

        return "define('DB_NAME', '" . $db . "');\n"
            . "define('DB_USER', '" . $user . "');\n"
            . "define('DB_PASSWORD', '" . $pass . "');\n"
            . "define('DB_HOST', 'localhost');\n"
            . "\$table_prefix = 'wp_';\n";
    }

    private function genericFile(int $seed): string
    {
        $app = SubSeed::pick(['api', 'web', 'core', 'portal', 'service'], $seed, SubSeed::NS_REACTION, 'gen|app');
        $env = SubSeed::pick(['production', 'staging', 'development'], $seed, SubSeed::NS_REACTION, 'gen|env');
        $token = SubSeed::reroll('gen|token', static function (string $f) use ($seed): string {
            return SubSeed::chars($seed, SubSeed::NS_REACTION, $f, 'abcdef0123456789', 32);
        });

        return "[app]\n"
            . 'name = ' . $app . "\n"
            . 'environment = ' . $env . "\n"
            . 'secret = ' . $token . "\n"
            . "debug = false\n";
    }

    // --- redirect-notice -------------------------------------------------------------------------

    private function redirectNotice(int $seed, bool $html): ReactionFragment
    {
        $diag = SubSeed::pick(
            [
                'Gateway probe queued; awaiting upstream handshake.',
                'Upstream reachability check pending.',
                'Target validation in progress; no redirect issued.',
                'Proxy diagnostic recorded; destination not followed.',
            ],
            $seed,
            SubSeed::NS_REACTION,
            'redirect|diag'
        );

        if ($html) {
            return new ReactionFragment(
                "\n<section class=\"redirect-check\"><p>Validating upstream target: <code>",
                '</code></p><p>' . $diag . "</p></section>\n",
                true
            );
        }

        return new ReactionFragment("\nvalidating upstream target: ", "\n" . $diag . "\n", true);
    }

    // --- debug-view (never displays the value) ---------------------------------------------------

    private function debugView(int $seed, bool $html): ReactionFragment
    {
        $trace = $this->debugTrace($seed);

        if ($html) {
            return new ReactionFragment(
                "\n<section class=\"debug-panel\"><h2>Application debug</h2><pre>" . $trace . "</pre></section>\n",
                '',
                false
            );
        }

        return new ReactionFragment("\n--- application debug ---\n" . $trace . "\n", '', false);
    }

    private function debugTrace(int $seed): string
    {
        $file = SubSeed::pick(['Controller', 'Kernel', 'Router', 'Middleware', 'Handler'], $seed, SubSeed::NS_REACTION, 'debug|file');
        $env = SubSeed::pick(['production', 'staging'], $seed, SubSeed::NS_REACTION, 'debug|env');
        $line = 20 + SubSeed::index($seed, SubSeed::NS_REACTION, 'debug|line', 400);

        return "mode: enabled\n"
            . 'environment: ' . $env . "\n"
            . "runtime: 8.1\n"
            . "trace:\n"
            . '  #0 /var/www/app/src/Http/' . $file . '.php(' . $line . ")\n"
            . "  #1 /var/www/app/public/index.php(19)\n";
    }

    // --- command-result --------------------------------------------------------------------------

    private function commandResult(string $value, int $seed, bool $html): ReactionFragment
    {
        $out = $this->commandOutput($this->firstToken($value), $seed);

        if ($html) {
            return new ReactionFragment(
                "\n<section class=\"terminal\"><pre>$ ",
                "\n" . $out . "</pre></section>\n",
                true
            );
        }

        return new ReactionFragment("\n$ ", "\n" . $out . "\n", true);
    }

    /** The leading ASCII-letter run of the value, lower-cased and bounded — a closed lexical key. */
    private function firstToken(string $value): string
    {
        if (preg_match('/^[a-z]{1,16}/i', $value, $m) === 1) {
            return strtolower($m[0]);
        }

        return '';
    }

    private function commandOutput(string $token, int $seed): string
    {
        switch ($token) {
            case 'id':
                return rtrim(CannedData::uid($seed), "\n");
            case 'whoami':
                return 'www-data';
            case 'uname':
                return 'Linux ' . rtrim(CannedData::hostname($seed), "\n") . ' 5.15.0 x86_64 GNU/Linux';
            case 'pwd':
                return '/var/www/' . SubSeed::pick(['html', 'app', 'public', 'current'], $seed, SubSeed::NS_REACTION, 'cmd|pwd');
            case 'ls':
                $picked = SubSeed::subset(
                    ['index.php', 'config.php', 'README.md', 'composer.json', '.env', 'uploads', 'logs', 'vendor'],
                    5,
                    $seed,
                    SubSeed::NS_REACTION,
                    'cmd|ls'
                );

                return implode('  ', $picked);
            case 'cat':
                return 'cat: input: No such file or directory';
            default:
                return 'sh: command not found';
        }
    }

    // --- search-result ---------------------------------------------------------------------------

    private function searchResult(int $seed, bool $html): ReactionFragment
    {
        $count = 1 + SubSeed::index($seed, SubSeed::NS_REACTION, 'search|count', 48);
        $titles = SubSeed::subset(
            ['Getting started', 'Release notes', 'API reference', 'FAQ', 'Pricing', 'Support', 'Changelog', 'Roadmap'],
            3,
            $seed,
            SubSeed::NS_REACTION,
            'search|items'
        );

        if ($html) {
            $items = '';
            foreach ($titles as $title) {
                $items .= '<li>' . $title . '</li>';
            }

            return new ReactionFragment(
                "\n<section class=\"search-results\"><p>Results for <q>",
                '</q> (' . $count . ' matches)</p><ul>' . $items . "</ul></section>\n",
                true
            );
        }

        return new ReactionFragment(
            "\nsearch results for: ",
            ' (' . $count . " matches)\n" . implode("\n", $titles) . "\n",
            true
        );
    }
}
