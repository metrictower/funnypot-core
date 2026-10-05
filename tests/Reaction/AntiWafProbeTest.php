<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Reaction;

use Funnypot\Core\Reaction\AntiWafProbe;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * FP-0425: the two pure sqlmap-recon recognisers. The load-bearing property is SPECIFICITY — the
 * WAF-check recogniser must fire on sqlmap's fixed polyglot but NEVER on a generic union/information_schema
 * SQLi (else it would blind the honeypot's own SQLi decoys for a real attacker). Every miss fails open.
 */
final class AntiWafProbeTest extends TestCase
{
    /** sqlmap's fixed IPS_WAF_CHECK_PAYLOAD (lib/core/settings.py). */
    private const POLY = 'AND 1=1 UNION ALL SELECT 1,NULL,\'<script>alert("XSS")</script>\',table_name'
        . ' FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell(\'cat ../../../etc/passwd\')#';

    private function req(string $query = '', ?string $body = null): RequestContext
    {
        return new RequestContext('GET', '/index.php', $query, [], $body, 'x.test');
    }

    public function test_exact_polyglot_is_recognised(): void
    {
        self::assertTrue(AntiWafProbe::isWafCheckPolyglot($this->req('id=' . rawurlencode(self::POLY))));
    }

    public function test_url_encoded_polyglot_is_recognised_through_the_fold(): void
    {
        // Double-encode: proves the folded surface decodes it before the match.
        self::assertTrue(AntiWafProbe::isWafCheckPolyglot($this->req('q=' . rawurlencode(rawurlencode(self::POLY)))));
    }

    public function test_polyglot_in_the_body_is_recognised(): void
    {
        self::assertTrue(AntiWafProbe::isWafCheckPolyglot($this->req('', 'id=' . rawurlencode(self::POLY))));
    }

    public function test_generic_union_information_schema_sqli_is_NOT_recognised(): void
    {
        // A real attacker's generic extraction — union + information_schema but NO xp_cmdshell, NO script
        // literal. MUST be false so it still reaches the SQLi decoys.
        $generic = '1 UNION ALL SELECT table_name,2 FROM information_schema.tables';
        self::assertFalse(AntiWafProbe::isWafCheckPolyglot($this->req('id=' . rawurlencode($generic))));
    }

    public function test_two_of_three_anchors_do_NOT_suppress(): void
    {
        // information_schema.tables + xp_cmdshell but no <script>alert("XSS")</script> literal.
        $partial = "information_schema.tables ; EXEC xp_cmdshell('whoami')";
        self::assertFalse(AntiWafProbe::isWafCheckPolyglot($this->req('id=' . rawurlencode($partial))));
        // the script literal + information_schema but no xp_cmdshell.
        $partial2 = '<script>alert("XSS")</script> FROM information_schema.tables';
        self::assertFalse(AntiWafProbe::isWafCheckPolyglot($this->req('id=' . rawurlencode($partial2))));
    }

    public function test_benign_request_is_not_recognised(): void
    {
        self::assertFalse(AntiWafProbe::isWafCheckPolyglot($this->req('id=1')));
        self::assertFalse(AntiWafProbe::isWafCheckPolyglot($this->req('q=' . rawurlencode('best union jack flag'))));
    }

    public function test_heuristic_alphabet_is_recognised(): void
    {
        // 10 chars from " ' ) ( , . with exactly one ' and one ".
        self::assertTrue(AntiWafProbe::isHeuristicAlphabet($this->req('id=' . rawurlencode('\'"()(),.()'))));
    }

    public function test_heuristic_alphabet_in_the_body_is_recognised(): void
    {
        self::assertTrue(AntiWafProbe::isHeuristicAlphabet($this->req('', 'x=' . rawurlencode('(.,"()\'().'))));
    }

    public function test_heuristic_alphabet_near_misses_are_rejected(): void
    {
        self::assertFalse(AntiWafProbe::isHeuristicAlphabet($this->req('id=' . rawurlencode('\'"()(),.('))), '9 chars');
        self::assertFalse(AntiWafProbe::isHeuristicAlphabet($this->req('id=' . rawurlencode('\'"()(),.()('))), '11 chars');
        self::assertFalse(AntiWafProbe::isHeuristicAlphabet($this->req('id=' . rawurlencode('\'\'"()(),..'))), 'two single quotes');
        self::assertFalse(AntiWafProbe::isHeuristicAlphabet($this->req('id=' . rawurlencode('abc\'"().,x'))), 'out-of-alphabet char');
        self::assertFalse(AntiWafProbe::isHeuristicAlphabet($this->req('id=' . rawurlencode('()(),.()()'))), 'no quotes at all');
    }
}
