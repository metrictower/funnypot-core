<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0581: the unix/windows command-injection oracles keyed `[;|&\n`]\s*<recon>` — so a query-string
 * `&` param delimiter before a param literally named id/pwd/uname/ipconfig/... was read as a shell
 * background operator and classified the benign request as command injection. The `(?![=\w])` token
 * guard fixes it: a recon word that is a param KEY (`&id=`) or an identifier prefix (`&idle=`) no longer
 * matches, while the genuine shell forms still do.
 */
final class CmdiParamKeyFalsePositiveTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        // Isolated origin + authorizer so a genuine cmdi match that reflects is served, not suppressed.
        $cfg = new Config('respond', null, 'matched-only', null, 'coherent', Style::REALISTIC, 'critical', 65536, 0, 0, false);
        $cfg->isolatedOrigin = true;
        $cfg->attackEmulation = true;
        $cfg->reflectorAuthorizer = static function (RequestContext $r, string $class): bool { return true; };

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function ruleId(string $query): ?string
    {
        // Store-MISS path so the request reaches the linear attack scan where the cmdi rules live.
        $r = $this->engine()->respond(new RequestContext('GET', '/x', $query, [], null, 'x.test'), SiteProfile::empty(), 's');

        return $r !== null && $r->servedBy !== null ? ($r->servedBy->ruleId ?? null) : null;
    }

    public function test_benign_param_keys_do_not_classify_as_command_injection(): void
    {
        // A `&`-delimited param whose key happens to be a recon word must NOT hit the cmdi oracles.
        foreach ([
            'a=1&id=7', 'user=bob&pwd=x', 'a=1&uname=linux', 'x=1&ifconfig=eth0', 'p=1&id=42',
            'b=2&ipconfig=x', 'c=3&systeminfo=y', 'd=4&dir=/tmp', 'e=5&idle=1',
        ] as $q) {
            $id = $this->ruleId($q);
            self::assertNotSame('attack-cmdi-unix', $id, $q);
            self::assertNotSame('attack-cmdi-windows', $id, $q);
        }
    }

    public function test_genuine_unix_command_injection_still_classifies(): void
    {
        foreach ([';id', '|whoami', '`id`', '$(id)', ';%20id', 'x%26%26id', '%0aid', 'a;uname'] as $raw) {
            self::assertSame('attack-cmdi-unix', $this->ruleId('q=' . $raw), $raw);
        }
    }

    public function test_bareword_argument_commands_still_classify(): void
    {
        // The `cat\s`/`ls\s` branches require trailing whitespace, so they must stay UNGUARDED: a cmdi
        // payload whose recon command takes a bareword argument (not a well-known /etc/passwd path that a
        // higher-priority LFI rule would claim) must still hit the unix oracle. Guards the regression the
        // over-broad first attempt introduced (FP-0581 review Finding 1).
        foreach ([';cat passwd', ';cat secret', ';ls secret', ';ls tmp'] as $raw) {
            self::assertSame('attack-cmdi-unix', $this->ruleId('q=' . rawurlencode($raw)), $raw);
        }
    }

    public function test_genuine_windows_command_injection_still_classifies(): void
    {
        foreach (['|ipconfig', ';systeminfo', '`ipconfig`', '$(systeminfo)'] as $raw) {
            self::assertSame('attack-cmdi-windows', $this->ruleId('q=' . $raw), $raw);
        }
        // Bareword-argument windows commands (unguarded `type\s`, and `dir` + arg) must still classify.
        foreach ([';type web.config', ';dir secret'] as $raw) {
            self::assertSame('attack-cmdi-windows', $this->ruleId('q=' . rawurlencode($raw)), $raw);
        }
    }
}
