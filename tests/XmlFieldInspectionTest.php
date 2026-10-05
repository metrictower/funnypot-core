<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\BoundedInspection;
use PHPUnit\Framework\TestCase;

/**
 * FP-0369b: XML per-field inspection. An XML/+xml body flattens through the SAME bodyFields()/fieldSurfaces()
 * /`in: fields` seam as JSON/urlencoded/multipart — element names, attribute values, and char-data/CDATA
 * become discrete fields. XXE-SAFE BY CONSTRUCTION: a bounded pure-string scan, no XML parser, so no entity
 * is ever resolved, no DTD/external-entity/network fetch occurs, and billion-laughs cannot amplify.
 */
final class XmlFieldInspectionTest extends TestCase
{
    /** @return array<int,array{kind:string,v:string}> */
    private function fields(string $contentType, string $body): array
    {
        return BoundedInspection::bodyFields(new RequestContext('POST', '/x', '', ['Content-Type' => $contentType], $body));
    }

    /** @return string[] */
    private function values(string $contentType, string $body): array
    {
        $out = [];
        foreach ($this->fields($contentType, $body) as $f) {
            if ($f['kind'] === 'value') {
                $out[] = $f['v'];
            }
        }

        return $out;
    }

    public function test_element_names_attributes_and_chardata_become_fields(): void
    {
        $f = $this->fields('application/xml', '<order id="42"><user role="admin">alice</user></order>');
        $names = array_values(array_map(static fn ($e) => $e['v'], array_filter($f, static fn ($e) => $e['kind'] === 'name')));
        self::assertSame(['order', 'user'], $names);
        self::assertContains('42', $this->values('application/xml', '<order id="42"></order>'), 'attribute value is a field');
        self::assertContains('admin', $this->values('application/xml', '<u role="admin">x</u>'), 'attribute value is a field');
        self::assertContains('alice', $this->values('application/xml', '<u>alice</u>'), 'char-data is a field');
    }

    public function test_content_type_routing_json_text_and_plus_xml(): void
    {
        foreach (['application/xml', 'text/xml', 'application/soap+xml', 'application/atom+xml'] as $ct) {
            self::assertContains('whoami', $this->values($ct, '<s:Body><cmd>whoami</cmd></s:Body>'), "{$ct} must flatten to fields");
        }
        // A non-XML content type keeps the blob fallback (no per-field view).
        self::assertSame([], $this->fields('text/plain', '<x>y</x>'));
    }

    public function test_single_and_double_quoted_attributes(): void
    {
        $vals = $this->values('application/xml', "<a href=\"d\" title='s'></a>");
        self::assertContains('d', $vals);
        self::assertContains('s', $vals);
    }

    public function test_cdata_content_is_a_matchable_field(): void
    {
        self::assertContains('<script>alert(1)</script>', $this->values('text/xml', '<x><![CDATA[<script>alert(1)</script>]]></x>'));
    }

    // --- XXE safety (the whole point) --------------------------------------------------------------

    public function test_external_entity_is_never_resolved(): void
    {
        $xxe = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>';
        $blob = json_encode($this->fields('application/xml', $xxe));
        // The DOCTYPE/ENTITY is skipped and &xxe; stays literal — the file target never appears as a field.
        self::assertStringNotContainsString('passwd', (string) $blob, 'no file:// target leaks — the entity is never resolved');
        self::assertStringNotContainsString('file://', (string) $blob);
        self::assertContains('&xxe;', $this->values('application/xml', $xxe), 'the entity reference stays literal text');
    }

    public function test_billion_laughs_cannot_amplify(): void
    {
        $lol = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>'
            . '<root>&lol2;</root>';
        $fields = $this->fields('application/xml', $lol);
        // Nothing expands (pure-string scan): bounded field count, the body stays inert.
        self::assertLessThanOrEqual(BoundedInspection::MAX_BODY_FIELDS, count($fields));
        self::assertContains('&lol2;', $this->values('application/xml', $lol), 'nested entity reference stays literal');
    }

    public function test_doctype_and_processing_instruction_are_skipped_not_emitted(): void
    {
        $f = $this->fields('application/xml', '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE html><page><t>ok</t></page>');
        $names = array_map(static fn ($e) => $e['v'], array_filter($f, static fn ($e) => $e['kind'] === 'name'));
        self::assertNotContains('?xml', $names, 'the XML declaration is not an element');
        self::assertNotContains('!DOCTYPE', $names, 'the DOCTYPE is not an element');
        self::assertContains('ok', $this->values('application/xml', '<page><t>ok</t></page>'));
    }

    public function test_malformed_xml_does_not_throw(): void
    {
        // Best-effort: whatever scanned, no exception, never a blob-spanning match.
        $this->fields('text/xml', '<broken attr=unclosed <<< &;');
        $this->fields('text/xml', '<<<<');
        $this->fields('application/xml', '');
        self::assertTrue(true);
    }

    public function test_field_count_is_bounded(): void
    {
        $body = '<root>' . str_repeat('<n a="v">t</n>', 2000) . '</root>';
        self::assertLessThanOrEqual(BoundedInspection::MAX_BODY_FIELDS, count($this->fields('application/xml', $body)));
    }
}
