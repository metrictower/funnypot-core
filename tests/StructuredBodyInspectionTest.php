<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Support\BoundedInspection;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0369 — structured request-body inspection: the body is flattened by content-type into per-field
 * values matched in isolation (no cross-field regex span), each FP-0356-folded. Proves the flattening,
 * the shipped `in: fields.filename` webshell-upload rule (a genuinely-new win), malformed-degrade, and
 * the caps.
 */
final class StructuredBodyInspectionTest extends TestCase
{
    private function req(string $contentType, string $body, string $path = '/api/x'): RequestContext
    {
        return new RequestContext('POST', $path, '', ['Content-Type' => $contentType], $body);
    }

    // --- flattening (BoundedInspection::bodyFields / fieldSurfaces) --------------------------------

    public function test_json_flattens_to_value_and_key_path_fields(): void
    {
        $r = $this->req('application/json', '{"user":{"name":"1 union select 1"},"n":5}');
        $values = BoundedInspection::fieldSurfaces($r, '');
        // The nested value is exposed as its own field (per-field, not a blob) — this is the payoff.
        self::assertTrue($this->anyContains($values, 'union select 1'), 'nested json value must be a field');
        self::assertTrue($this->anyContains($values, 'user.name'), 'dotted key path must be a field');
    }

    public function test_urlencoded_flattens_names_and_values(): void
    {
        $r = $this->req('application/x-www-form-urlencoded', 'q=%3Cscript%3E&page=2');
        $values = BoundedInspection::fieldSurfaces($r, '');
        // %3Cscript%3E is folded per-field (FP-0356) so <script> is matchable.
        self::assertTrue($this->anyContains($values, '<script>'), 'urlencoded value folded per-field');
        self::assertTrue($this->anyContains($values, 'q'), 'urlencoded name is a field');
    }

    public function test_multipart_exposes_filename_field(): void
    {
        $body = "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php echo 1; ?>\r\n--B--\r\n";
        $r = $this->req('multipart/form-data; boundary=B', $body);
        $filenames = BoundedInspection::fieldSurfaces($r, 'filename');
        self::assertTrue($this->anyContains($filenames, 'shell.php'), 'multipart filename must be a filename-kind field');
        // filename is NOT in the value/name view unless requested.
        self::assertFalse($this->anyContains(BoundedInspection::fieldSurfaces($r, 'filename'), 'form-data'), 'disposition header is not a field');
    }

    public function test_unknown_and_malformed_bodies_degrade_to_empty(): void
    {
        self::assertSame([], BoundedInspection::fieldSurfaces($this->req('text/plain', 'hello'), ''));
        self::assertSame([], BoundedInspection::fieldSurfaces($this->req('application/json', 'not json{'), ''));
        self::assertSame([], BoundedInspection::fieldSurfaces($this->req('multipart/form-data', 'no boundary'), ''));
        self::assertSame([], BoundedInspection::fieldSurfaces(new RequestContext('POST', '/x', '', [], null), ''));
    }

    public function test_fields_are_separate_entries_no_cross_field_join(): void
    {
        // The structural anti-cross-field-FP guarantee: two adjacent values are SEPARATE list entries,
        // so a regex can never match across the boundary (e.g. 'ab' from 'a' + 'b').
        $r = $this->req('application/json', '{"a":"foo","b":"bar"}');
        $values = BoundedInspection::fieldSurfaces($r, '');
        foreach ($values as $v) {
            self::assertStringNotContainsString('foobar', $v, 'fields must not be concatenated');
        }
    }

    public function test_field_count_is_capped(): void
    {
        $pairs = [];
        for ($i = 0; $i < 1000; $i++) {
            $pairs[] = "k$i=v$i";
        }
        $r = $this->req('application/x-www-form-urlencoded', implode('&', $pairs));
        self::assertLessThanOrEqual(BoundedInspection::MAX_BODY_FIELDS, count(BoundedInspection::fieldSurfaces($r, '')));
    }

    // --- end-to-end: the shipped in:fields.filename webshell-upload rule --------------------------

    private function honeypot(): Honeypot
    {
        $config = new Config('respond', static function (RequestContext $r): bool {
            return true;
        }, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0, true);

        return Honeypot::default($config);
    }

    public function test_webshell_upload_by_filename_classifies_attack(): void
    {
        $body = "--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"cmd.php\"\r\n\r\n" . '<?php system("id"); ?>' . "\r\n--X--\r\n";
        $r = $this->req('multipart/form-data; boundary=X', $body, '/upload/handler');
        $verdict = $this->honeypot()->classify($r, SiteProfile::empty());
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification, 'a .php multipart upload must classify ATTACK_CLASS');
        self::assertContains('attack-webshell-upload-multipart', $verdict->detection->templateIds());
    }

    public function test_benign_image_upload_is_not_attack(): void
    {
        $body = "--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"holiday.jpg\"\r\n\r\n\xff\xd8\xff\xe0JFIF\r\n--X--\r\n";
        $r = $this->req('multipart/form-data; boundary=X', $body, '/upload/handler');
        $verdict = $this->honeypot()->classify($r, SiteProfile::empty());
        self::assertNotSame(Verdict::ATTACK_CLASS, $verdict->classification, 'a benign .jpg upload must not be an attack');
    }

    /** @param string[] $haystacks */
    private function anyContains(array $haystacks, string $needle): bool
    {
        foreach ($haystacks as $h) {
            if (strpos($h, $needle) !== false) {
                return true;
            }
        }

        return false;
    }
}
