<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SubSeed;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0389: the NTLM-over-HTTP information-leak decoy, end to end over the REAL compiled corpus. A bare
 * probe on an Exchange/IIS path gets a static 401 + `WWW-Authenticate: NTLM`; an NTLM Type-1 is upgraded
 * to a 401 whose Type-2 Target-Info leaks the deploy's canary AD names. It never authenticates, never
 * leaves a 404-upgrade (no 5xx / 3xx / session), and the served header is denylist-clean across seeds.
 */
final class NtlmChallengeDecoyTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const ID = 'attack-ntlm-exchange';

    // Artemis's exact Type-1 (Negotiate) token.
    private const TYPE1 = 'NTLM TlRMTVNTUAABAAAAMpCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw==';
    // A Type-3 (AUTHENTICATE) magic — "NTLMSSP\0" + type byte 0x03 => base64 prefix TlRMTVNTUAAD.
    private const TYPE3 = 'NTLM TlRMTVNTUAADAAAAGAAYAHAAAAAYABgAiAAAAA==';

    private const CLAIMED_PATHS = [
        '/owa/', '/ews/', '/rpc/', '/ecp/', '/powershell/',
        '/autodiscover/autodiscover.xml', '/EWS/Exchange.asmx',
        '/mapi/', '/microsoft-server-activesync/',
    ];

    /** @var array<string,mixed>|null */
    private static $indexCache;

    /** @return array<string,mixed> */
    private static function index(): array
    {
        if (self::$indexCache === null) {
            self::$indexCache = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$indexCache;
    }

    private function engine(string $seed = 'ntlm-fixed'): Honeypot
    {
        $cfg = $this->config($seed);

        return new Honeypot(new PhpArrayStore(self::index()), $cfg);
    }

    private function config(string $seed): Config
    {
        return new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only', null, 'coherent', Style::MINIMAL, 'high',
            65536, 0, 0, true /* attackEmulation */, null, null, null, $seed /* seedSalt => deploy material */
        );
    }

    /** @param array<string,string> $headers */
    private function resp(string $path, array $headers = [], string $method = 'GET', string $seed = 'ntlm-fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext($method, $path, '', $headers, null, 'x.test'));
    }

    /** Case-insensitive header lookup over the served response. */
    private function header(?object $r, string $name): ?string
    {
        foreach ((array) ($r->headers ?? []) as $k => $v) {
            if (strcasecmp((string) $k, $name) === 0) {
                return (string) $v;
            }
        }

        return null;
    }

    /** @return array<string,mixed> the isolated compiled rule */
    private function isolatedRule(): array
    {
        foreach ((require self::COMPILED) as $rule) {
            if (($rule['id'] ?? '') === self::ID) {
                return $rule;
            }
        }
        self::fail(self::ID . ' not compiled');
    }

    // --- AC1: bare probe => bare 401 on every claimed path x {GET,HEAD} ------------------------------

    public function test_ac1_bare_probe_is_a_bare_401_on_every_path(): void
    {
        foreach (self::CLAIMED_PATHS as $path) {
            foreach (['GET', 'HEAD'] as $method) {
                $r = $this->resp($path, [], $method);
                self::assertSame(401, $r->status ?? null, "{$method} {$path} must be 401");
                self::assertSame('NTLM', $this->header($r, 'WWW-Authenticate'), "{$method} {$path} bare NTLM");
            }
            // Content-Type is text/html on the GET (body-bearing) probe.
            self::assertStringContainsString(
                'text/html',
                (string) $this->header($this->resp($path), 'Content-Type'),
                "{$path} Content-Type"
            );
        }
    }

    // --- AC2/AC3: Type-1 => Type-2 whose AV_PAIRs are the deploy persona's AD names ------------------

    public function test_ac2_ac3_type1_emits_type2_leaking_persona_ad_names(): void
    {
        $seed = 'ntlm-fixed';
        $ps = $this->config($seed)->deploySeed();
        $persona = PersonaIdentity::fromSeed($ps);

        foreach (['/owa/', '/autodiscover/autodiscover.xml'] as $path) {
            $r = $this->resp($path, ['Authorization' => self::TYPE1], 'GET', $seed);
            self::assertSame(401, $r->status ?? null, "{$path} Type-1 must be 401");
            $hv = (string) $this->header($r, 'WWW-Authenticate');
            self::assertStringStartsWith('NTLM ', $hv, "{$path} WWW-Authenticate carries a blob");
            self::assertNotSame('NTLM', $hv, "{$path} must upgrade past the bare challenge");

            $raw = base64_decode(substr($hv, 5), true);
            self::assertNotFalse($raw, 'valid base64');
            $d = $this->decode($raw);
            self::assertSame("NTLMSSP\x00", $d['sig'], 'signature');
            self::assertSame(2, $d['msgType'], 'MessageType = CHALLENGE');

            self::assertSame($persona->field('windows.netbiosDomain'), $d['av'][0x0002] ?? null, 'nb domain');
            self::assertSame($persona->field('windows.netbiosComputer'), $d['av'][0x0001] ?? null, 'nb computer');
            self::assertSame($persona->field('windows.dnsDomain'), $d['av'][0x0004] ?? null, 'dns domain');
            self::assertSame($persona->field('windows.dnsComputer'), $d['av'][0x0003] ?? null, 'dns computer');
            self::assertSame($persona->field('windows.dnsForest'), $d['av'][0x0005] ?? null, 'dns tree');
        }
    }

    // --- AC4: owns_path overrides the pre-existing /EWS/Exchange.asmx 302 ----------------------------

    public function test_ac4_overrides_the_ews_exchange_asmx_302(): void
    {
        $r = $this->resp('/EWS/Exchange.asmx');
        self::assertSame(401, $r->status ?? null, '/EWS/Exchange.asmx must now be a 401, not the corpus 302');
        self::assertSame('NTLM', $this->header($r, 'WWW-Authenticate'));
    }

    // --- AC5: never authenticates (Type-3 / junk stay a bare 401, no cookie, no 3xx) -----------------

    public function test_ac5_type3_and_junk_authorization_stay_bare_401(): void
    {
        foreach ([self::TYPE3, 'Basic dXNlcjpwYXNz', 'garbage', 'NTLM not-a-token'] as $auth) {
            $r = $this->resp('/owa/', ['Authorization' => $auth]);
            self::assertSame(401, $r->status ?? null, "auth '{$auth}' must stay 401");
            self::assertSame('NTLM', $this->header($r, 'WWW-Authenticate'), "auth '{$auth}' stays bare NTLM");
            self::assertNull($this->header($r, 'Set-Cookie'), "auth '{$auth}' never sets a session cookie");
            $status = (int) ($r->status ?? 0);
            self::assertFalse($status >= 300 && $status < 400, "auth '{$auth}' is never a 3xx redirect");
        }
    }

    // --- AC7: degrade valve — a declining behavior falls back to the bare 401, never a 5xx -----------

    public function test_ac7_declining_behavior_degrades_to_bare_401(): void
    {
        // An emulator with NO persona seed: the handler reaches the same `return null` the exhausted
        // re-roll uses, so renderRule serves the base bare-401 — never a dirty header, never a 5xx.
        $emulator = new TemplateAttackEmulator([$this->isolatedRule()], [], null, null, [], null /* personaSeed */);
        $req = new RequestContext('GET', '/owa/', '', ['Authorization' => self::TYPE1], null, 'x.test');
        $out = $emulator->renderRule($this->isolatedRule(), [], 12345, $req);
        self::assertNotNull($out);
        self::assertSame(401, $out->status);
        self::assertSame('NTLM', $out->headers['WWW-Authenticate'] ?? null);
        // Exhaustion of the fingerprint re-roll shares this exact return path; AC9 proves the valve
        // never actually fires in production (the names leak for every seed).
    }

    // --- AC8: position-blind synthesize port (null request) => bare 401, no fatal --------------------

    public function test_ac8_null_request_degrades_to_bare_401(): void
    {
        $emulator = new TemplateAttackEmulator([$this->isolatedRule()], [], null, null, [], 999);
        $out = $emulator->renderRule($this->isolatedRule(), [], 999, null);
        self::assertNotNull($out);
        self::assertSame(401, $out->status);
        self::assertSame('NTLM', $out->headers['WWW-Authenticate'] ?? null);
    }

    // --- AC9: >=1200-seed fingerprint sweep of the served challenge ----------------------------------

    public function test_ac9_fingerprint_sweep_leaks_cleanly_for_every_seed(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $degradeValveFired = 0;
        for ($s = 1; $s <= 1200; $s++) {
            $seed = 'sweep-' . $s;
            $r = $this->resp('/owa/', ['Authorization' => self::TYPE1], 'GET', $seed);
            $hv = (string) $this->header($r, 'WWW-Authenticate');

            if ($hv === 'NTLM') {
                $degradeValveFired++;   // the behavior declined -> bare 401 (must be ~0)
                continue;
            }

            self::assertFalse(SubSeed::hitsDeniedDigits($hv), "seed {$seed} served a denied digit run");
            self::assertSame([], $guard->scanResponse('', ['WWW-Authenticate' => $hv]), "seed {$seed} tripped FingerprintGuard");
        }
        self::assertSame(0, $degradeValveFired, 'the names must leak for every deploy (valve fires 0 times)');
    }

    public function test_ac9_bare_401_fallback_is_also_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        for ($s = 0; $s < 200; $s++) {
            $r = $this->resp('/owa/', [], 'GET', 'bare-' . $s);
            self::assertSame([], $guard->scanResponse((string) ($r->body ?? ''), (array) ($r->headers ?? [])), "seed {$s} bare-401 tripped the guard");
        }
    }

    // --- an independent Type-2 decoder (AV_PAIR walk) ------------------------------------------------

    /** @return array<string,mixed> */
    private function decode(string $bytes): array
    {
        $sig = substr($bytes, 0, 8);
        $msgType = (int) unpack('V', substr($bytes, 8, 4))[1];
        $ti = unpack('vlen/vmax/Voff', substr($bytes, 40, 8));

        $av = [];
        $p = (int) $ti['off'];
        $end = $p + (int) $ti['len'];
        while ($p + 4 <= $end) {
            $id = (int) unpack('v', substr($bytes, $p, 2))[1];
            $len = (int) unpack('v', substr($bytes, $p + 2, 2))[1];
            $p += 4;
            if ($id === 0x0000) {
                break;
            }
            $av[$id] = $this->fromUtf16le(substr($bytes, $p, $len));
            $p += $len;
        }

        return ['sig' => $sig, 'msgType' => $msgType, 'av' => $av];
    }

    private function fromUtf16le(string $s): string
    {
        $out = '';
        for ($i = 0; $i < strlen($s); $i += 2) {
            $out .= $s[$i];
        }

        return $out;
    }
}
