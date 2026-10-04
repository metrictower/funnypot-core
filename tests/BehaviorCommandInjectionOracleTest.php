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
 * FP-0466 (Stage 1): the multi-dialect arithmetic command-injection oracle. Generalises FP-0386's
 * POSIX-mul-only reflector to +/-/* across three dialects — POSIX arithmetic-expansion `$((A op B))`
 * (42, incl. the inner `$(echo MID)` Commix shape), the POSIX `expr` utility (49), and Windows cmd.exe
 * `set /a` (51). All compute via Support\SafeArithmetic (zero exec) and reflect {left}{result}{...}{right}
 * for the attacker's own anchor tokens, reflector-gated (reflect_class: cmdi) exactly like FP-0386.
 *
 * Stage 1 excludes the shell-deobfuscate decoder (${IFS}/escaped-\*), which ships as a separate stage.
 */
final class BehaviorCommandInjectionOracleTest extends TestCase
{
    /** @var array<string,mixed> */
    private static function index(): array
    {
        return require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    }

    private function engine(bool $isolated = true, bool $authorized = true): Honeypot
    {
        $cfg = new Config('respond', null, 'matched-only', null, 'coherent', Style::REALISTIC, 'high', 65536, 0, 0, false);
        $cfg->isolatedOrigin = $isolated;
        $cfg->attackEmulation = true;
        $cfg->reflectorAuthorizer = static function (RequestContext $r, string $class) use ($authorized): bool {
            return $authorized;
        };

        return new Honeypot(new PhpArrayStore(self::index()), $cfg);
    }

    private function probe(string $raw): RequestContext
    {
        return new RequestContext('GET', '/x', 'q=' . rawurlencode($raw), [], null, 'x.test');
    }

    private function body(?object $resp): string
    {
        return $resp !== null ? (string) $resp->body : '';
    }

    private function serve(string $raw, bool $isolated = true, bool $authorized = true): string
    {
        return $this->body($this->engine($isolated, $authorized)->respond($this->probe($raw), SiteProfile::empty(), 's'));
    }

    // ---- AC1: operators +,-,* (POSIX arithmetic expansion) -------------------------------------

    public function test_posix_addition(): void
    {
        self::assertStringContainsString('ABCDEF' . (23 + 19) . 'ZYXWVU', $this->serve('echo ABCDEF$((23+19))ZYXWVU'));
    }

    public function test_posix_subtraction(): void
    {
        self::assertStringContainsString('ABCDEF' . (90 - 48) . 'ZYXWVU', $this->serve('echo ABCDEF$((90-48))ZYXWVU'));
    }

    public function test_posix_multiplication(): void
    {
        self::assertStringContainsString('ABCDEF' . (6 * 7) . 'ZYXWVU', $this->serve('echo ABCDEF$((6*7))ZYXWVU'));
    }

    // ---- AC2/AC3: the classic Commix inner $(echo MID) confirmation ----------------------------

    public function test_commix_inner_echo_mid_shape(): void
    {
        // echo ABCDEF$((23+19))$(echo ABCDEF)ABCDEF  =>  ABCDEF42ABCDEFABCDEF
        self::assertStringContainsString('ABCDEF42ABCDEFABCDEF', $this->serve('echo ABCDEF$((23+19))$(echo ABCDEF)ABCDEF'));
    }

    // ---- AC3: POSIX expr utility dialect -------------------------------------------------------

    public function test_expr_utility_dialect(): void
    {
        self::assertStringContainsString('TAG123' . (15 + 27) . 'TAG123', $this->serve('echo TAG123$(expr 15 + 27)TAG123'));
    }

    public function test_expr_backtick_form(): void
    {
        self::assertStringContainsString('QWERTY' . (8 * 9) . 'QWERTY', $this->serve('QWERTY`expr 8 * 9`QWERTY'));
    }

    // ---- AC4-win: Windows set /a dialect -------------------------------------------------------

    public function test_windows_seta_framed(): void
    {
        self::assertStringContainsString('WTAG' . (15 + 27) . 'WTAG', $this->serve('echo WTAG& set /a 15+27 &echo WTAG'));
    }

    public function test_windows_seta_bare(): void
    {
        // cmd /c "set /a (15+27)"  => the sum appears (bare, no anchors)
        self::assertStringContainsString((string) (15 + 27), $this->serve('cmd /c "set /a (15+27)"'));
    }

    // ---- AC4: obfuscation (shell-deobfuscate decoder, Stage 2) ---------------------------------

    public function test_ifs_obfuscated_posix_probe_is_normalised(): void
    {
        // echo${IFS}ABCDEF$((10+5))ABCDEF  -> ${IFS} folds to a space -> matches 42.
        self::assertStringContainsString('ABCDEF' . (10 + 5) . 'ABCDEF', $this->serve('echo${IFS}ABCDEF$((10+5))ABCDEF'));
    }

    public function test_escaped_multiplication_expr_is_normalised(): void
    {
        // TAG999$(expr 6 \* 7)TAG999  -> the backslash is stripped -> `expr 6 * 7` matches 49.
        self::assertStringContainsString('TAG999' . (6 * 7) . 'TAG999', $this->serve('TAG999$(expr 6 \\* 7)TAG999'));
    }

    public function test_percent_then_ifs_obfuscation_folds(): void
    {
        // A percent-encoded ${IFS}: percent-decode then shell-deobfuscate both fire in the fold.
        $raw = 'echo%24%7BIFS%7DABCDEF%24%28%2810%2B5%29%29ABCDEF';
        $resp = $this->engine(true, true)->respond(new RequestContext('GET', '/x', 'q=' . $raw, [], null, 'x.test'));
        self::assertStringContainsString('ABCDEF' . (10 + 5) . 'ABCDEF', $this->body($resp));
    }

    // ---- AC6: compute, not echo ----------------------------------------------------------------

    public function test_computes_not_echoes_the_expression(): void
    {
        $b = $this->serve('echo ABCDEF$((4321+8765))ZYXWVU');
        self::assertStringContainsString('ABCDEF' . (4321 + 8765) . 'ZYXWVU', $b);
        self::assertStringNotContainsString('4321+8765', $b, 'the raw A op B must not be echoed verbatim');
    }

    // ---- AC7: no markup reaches the body (alnum anchors) ---------------------------------------

    public function test_no_markup_in_body(): void
    {
        $b = $this->serve('echo ' . str_repeat('A', 16) . '$((11*11))' . str_repeat('B', 16));
        self::assertStringNotContainsString('<', $b);
        self::assertStringNotContainsString('>', $b);
    }

    // ---- AC8: decline -> base page, never 500 --------------------------------------------------

    public function test_overflow_declines_to_base_page(): void
    {
        $resp = $this->engine(true)->respond($this->probe('echo ABCDEF$((9999999999*9999999999))ZYXWVU'), SiteProfile::empty(), 's');
        self::assertNotNull($resp, 'the rule still matches/serves; the expression declines to the base page');
        self::assertSame(200, $resp->status, 'a declined expression must still be 200, never a 500');
        // The base page carries no reflected anchor and no computed product.
        self::assertStringNotContainsString('ABCDEF', $this->body($resp), 'no anchor may be reflected on decline');
        self::assertStringContainsString('uid=0(root)', $this->body($resp), 'decline falls to the marker-free base page');
    }

    // ---- AC9/AC10: embedded + unauthorized suppress the reflection -----------------------------

    /** @return string[] one probe per dialect, each computing 42 */
    private static function dialectProbes(): array
    {
        return ['echo ABCDEF$((23+19))ZYXWVU', 'echo TAG123$(expr 15 + 27)TAG123', 'echo WTAG& set /a 15+27 &echo WTAG'];
    }

    public function test_embedded_host_suppresses_but_still_detects_every_dialect(): void
    {
        $e = $this->engine(false, true); // embedded origin, authorized
        foreach (self::dialectProbes() as $p) {
            $r = $this->probe($p);
            // Detection is still recorded (classification is attack-class on a cmdi rule)...
            $v = $e->classify($r, SiteProfile::empty());
            self::assertStringStartsWith('attack-cmdi', (string) ($v->fakeHandle->ruleId ?? ''), "embedded must still DETECT: {$p}");
            // ...but the reflection is withheld (no serve).
            self::assertNull($e->respond($r), "embedded must WITHHOLD the reflection: {$p}");
        }
    }

    public function test_unauthorized_suppresses_but_still_detects_every_dialect(): void
    {
        $e = $this->engine(true, false); // isolated origin, authorizer declines
        foreach (self::dialectProbes() as $p) {
            $r = $this->probe($p);
            $v = $e->classify($r, SiteProfile::empty());
            self::assertStringStartsWith('attack-cmdi', (string) ($v->fakeHandle->ruleId ?? ''), "unauthorized must still DETECT: {$p}");
            self::assertNull($e->respond($r), "unauthorized must WITHHOLD the reflection: {$p}");
        }
    }

    public function test_position_blind_synthesize_port_never_reflects(): void
    {
        // AC11: the request-less synthesize() port cannot prove isolated origin, so it never reflects.
        $e = $this->engine(true, true);
        $r = $this->probe('echo ABCDEF$((23+19))ZYXWVU');
        $v = $e->classify($r, SiteProfile::empty());
        self::assertStringStartsWith('attack-cmdi', (string) ($v->fakeHandle->ruleId ?? ''));
        // synthesize() WITHOUT a request is the position-blind port: it cannot prove isolated origin.
        self::assertNull($e->synthesize($v, SiteProfile::empty(), 's'), 'position-blind port must not reflect');
    }

    public function test_windows_seta_does_not_match_benign_word_boundary_text(): void
    {
        // FP-0466 review: a benign path/word ending in "set/a" must NOT trigger the Windows rule.
        foreach (['/reports/dataset/a 2024-01', 'charset/a 2024-01', 'see offset/a 2024-01 for details'] as $benign) {
            $v = $this->engine(true, true)->classify($this->probe($benign), SiteProfile::empty());
            self::assertNotSame('attack-cmdi-winarith', (string) ($v->fakeHandle->ruleId ?? ''), "benign must not match: {$benign}");
        }
    }

    // ---- FP-0386 backreference: the hex/mul Artemis classic still confirms ----------------------

    public function test_fp0386_artemis_classic_still_confirms(): void
    {
        $marker = 'abcdef1234' . (1234 * 5678) . 'fedcba99';
        self::assertStringContainsString($marker, $this->serve('echo abcdef1234$((1234*5678))fedcba99'));
    }
}
