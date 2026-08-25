<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Crs;

use Funnypot\Core\Compiler\Crs\CrsRule;
use Funnypot\Core\Compiler\Crs\CrsRuleParser;
use Funnypot\Core\Compiler\Crs\CrsSeverity;
use PHPUnit\Framework\TestCase;

/**
 * The CRS `.conf` parser, checked against a committed sample of real CoreRuleSet rules
 * (tests/fixtures/crs/rules) so nothing here touches the network.
 */
final class CrsRuleParserTest extends TestCase
{
    /** @return array<string,CrsRule> keyed by CRS rule id */
    private function rules(): array
    {
        $out = [];
        foreach ((new CrsRuleParser())->parseDir(__DIR__ . '/../fixtures/crs/rules') as $rule) {
            $out[$rule->id] = $rule;
        }

        return $out;
    }

    public function test_parses_every_secrule_including_multiline_actions(): void
    {
        $rules = $this->rules();
        self::assertCount(8, $rules);
        self::assertArrayHasKey('942140', $rules);
    }

    public function test_rx_operator_and_argument_are_extracted(): void
    {
        $rule = $this->rules()['942140'];
        self::assertSame('rx', $rule->operator);
        self::assertFalse($rule->negated);
        self::assertStringContainsString('information_schema', $rule->argument);
        self::assertStringStartsWith('(?i)', $rule->argument);
    }

    public function test_attack_class_and_paranoia_and_severity_are_read_from_tags(): void
    {
        $rule = $this->rules()['942140'];
        self::assertSame('sqli', $rule->attackClass);
        self::assertSame(1, $rule->paranoiaLevel);
        self::assertSame('CRITICAL', $rule->severity);
        self::assertContains('attack-sqli', $rule->tags);
    }

    public function test_opaque_libinjection_operators_are_recognised_verbatim(): void
    {
        self::assertSame('detectSQLi', $this->rules()['942100']->operator);
        self::assertSame('detectXSS', $this->rules()['941100']->operator);
    }

    public function test_negated_response_side_rule_is_flagged(): void
    {
        $rule = $this->rules()['951100'];
        self::assertTrue($rule->negated);
        self::assertTrue($rule->isResponseSide());
        self::assertNull($rule->attackClass);
    }

    public function test_pmfromfile_argument_is_the_data_filename(): void
    {
        $rule = $this->rules()['930120'];
        self::assertSame('pmFromFile', $rule->operator);
        self::assertSame('lfi-os-files.data', $rule->argument);
    }

    public function test_paranoia_level_two_rule_is_readable(): void
    {
        self::assertSame(2, $this->rules()['942421']->paranoiaLevel);
    }

    public function test_msg_and_logdata_are_never_captured(): void
    {
        // The parser must not expose CRS's own audit vocabulary — a fingerprint if it ever
        // reached a response. Only id/operator/argument/tags/severity are kept.
        $rule = $this->rules()['942140'];
        self::assertFalse(property_exists($rule, 'msg'));
        self::assertFalse(property_exists($rule, 'logdata'));
        foreach ($rule->tags as $tag) {
            self::assertStringNotContainsString('SQL Injection Attack', $tag);
        }
    }

    public function test_severity_mapping_respects_the_default_ceiling(): void
    {
        self::assertSame('high', CrsSeverity::map('CRITICAL'));
        self::assertSame('medium', CrsSeverity::map('ERROR'));
        self::assertSame('low', CrsSeverity::map('WARNING'));
        self::assertSame('low', CrsSeverity::map('NOTICE'));
    }
}
