<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Crs;

use Funnypot\Core\Compiler\Crs\CrsCompiler;
use PHPUnit\Framework\TestCase;

/**
 * Compiles the committed CRS fixture sample into funnypot attack templates and asserts the
 * aggregation contract: one broadened template per class, behind the existing per-class
 * response archetype, with the portability filter's skips audited.
 */
final class CrsCompilerTest extends TestCase
{
    /** @return array<string,mixed> */
    private function compile(int $pl = 1): array
    {
        return (new CrsCompiler(dirname(__DIR__, 2)))->compile(__DIR__ . '/../fixtures/crs/rules', $pl);
    }

    /** @return array<string,array<string,mixed>> templates keyed by id */
    private function templates(int $pl = 1): array
    {
        $out = [];
        foreach ($this->compile($pl)['templates'] as $t) {
            $out[$t['id']] = $t;
        }

        return $out;
    }

    public function test_one_template_per_class_that_has_an_archetype(): void
    {
        $ids = array_keys($this->templates());
        sort($ids);
        // rce has no rule in the fixture sample, so only sqli/xss/lfi are emitted.
        self::assertSame(['attack-crs-lfi', 'attack-crs-sqli', 'attack-crs-xss'], $ids);
    }

    public function test_aggregated_regex_matches_a_crs_only_sqli_payload(): void
    {
        $rx = $this->templates()['attack-crs-sqli']['match'][0]['regex'];
        // sqlite_master is a CRS DB-name pattern (942140), NOT in funnypot's own 50-sqli rule.
        self::assertSame(1, preg_match('~' . $rx . '~i', 'select * from sqlite_master'));
        self::assertSame(0, preg_match('~' . $rx . '~i', 'ordinary search text'));
    }

    public function test_lfi_template_folds_both_rx_and_pmfromfile(): void
    {
        $rx = $this->templates()['attack-crs-lfi']['match'][0]['regex'];
        self::assertSame(1, preg_match('~' . $rx . '~i', '/../../etc/'));         // 930110 @rx
        self::assertSame(1, preg_match('~' . $rx . '~i', 'file=/etc/passwd'));    // 930120 @pmFromFile phrase
    }

    public function test_response_body_reuses_the_existing_class_archetype(): void
    {
        $t = $this->templates();
        self::assertStringContainsString('SQL syntax', $t['attack-crs-sqli']['response']['body']);
        // FP-0190: the LFI catch-all no longer reuses the passwd body — that reused /etc/passwd for ANY
        // unmapped traversal (a collision tell). The recognizable targets are owned by the higher-priority
        // hand-authored LFI tier; this catch-all serves a believable file-absent read for the long tail.
        self::assertStringNotContainsString('{{canned.passwd}}', $t['attack-crs-lfi']['response']['body']);
        self::assertStringContainsString('No such file or directory', $t['attack-crs-lfi']['response']['body']);
    }

    public function test_generated_templates_never_reflect_attacker_input(): void
    {
        foreach ($this->templates() as $t) {
            $body = $t['response']['body'];
            self::assertStringNotContainsString('{{match', $body);
            self::assertStringNotContainsString('capture', json_encode($t['match']));
        }
    }

    public function test_severity_and_provenance_tags(): void
    {
        $t = $this->templates()['attack-crs-sqli'];
        self::assertSame('high', $t['severity']);          // CRS CRITICAL -> high, respects the default ceiling
        self::assertContains('crs', $t['tags']);
        self::assertContains('crs-pl1', $t['tags']);
        self::assertContains('sqli', $t['tags']);
    }

    public function test_priority_keeps_crs_behind_hand_authored_rules(): void
    {
        // Hand-authored attack templates use priority 31-90; CRS must sort after them so
        // first-match-wins keeps the specific rule ahead of the broad alternation.
        foreach ($this->templates() as $t) {
            self::assertGreaterThan(900, $t['priority']);
        }
    }

    public function test_portability_filter_audits_every_skip(): void
    {
        $skipped = [];
        foreach ($this->compile()['skipped'] as $s) {
            $skipped[$s['id']] = $s['reason'];
        }
        self::assertSame('opaque-operator:@detectSQLi', $skipped['942100']);
        self::assertSame('opaque-operator:@detectXSS', $skipped['941100']);
        self::assertSame('paranoia-level/2', $skipped['942421']);
        self::assertSame('negated-operator', $skipped['951100']);
    }

    public function test_paranoia_two_opt_in_admits_the_pl2_rule(): void
    {
        $skipped = array_column($this->compile(2)['skipped'], 'reason', 'id');
        self::assertArrayNotHasKey('942421', $skipped);   // no longer skipped at PL2
    }

    public function test_manifest_records_source_and_counts(): void
    {
        $manifest = $this->compile()['manifest'];
        self::assertSame('coreruleset', $manifest['source']);
        self::assertSame(1, $manifest['paranoia_level_max']);
        self::assertSame(4, $manifest['rules_kept']);
    }
}
