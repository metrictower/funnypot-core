<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\ParamRouteCompiler;
use Funnypot\Rules\PhpLiteralValidator;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Yaml\Yaml;

/**
 * The param-route compiler: turns a parameterized path template into a prefix-bucket index of
 * attack-rule-shaped entries. Build-time guards make "compiles but silently wrong" a build
 * failure — an unbucketable root param, an over-full bucket, a typo'd directive, or an id that
 * collides within the param set or with the attack set (they share the runtime ruleById id-space).
 */
final class ParamRouteCompilerTest extends TestCase
{
    /** @var string */
    private $tmp;

    /** @var int */
    private $seq = 0;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/funnypot-param-' . bin2hex(random_bytes(6));
        mkdir($this->tmp, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->rmrf($this->tmp);
    }

    /**
     * @param array<int,array<string,mixed>> $docs
     * @param string[]                       $reserved
     * @return array{schema:int,buckets:array<string,array<int,array<string,mixed>>>}
     */
    private function compile(array $docs, array $reserved = []): array
    {
        $dir = $this->tmp . '/p' . (++$this->seq);
        mkdir($dir, 0777, true);
        $i = 0;
        foreach ($docs as $doc) {
            file_put_contents($dir . '/' . sprintf('%02d', $i) . '-t.yaml', Yaml::dump($doc, 6, 2));
            $i++;
        }

        return (new ParamRouteCompiler())->compile($dir, $reserved);
    }

    /** @return array<string,mixed> */
    private function doc(string $id, string $path, array $extra = []): array
    {
        return array_merge([
            'id' => $id,
            'param' => ['method' => 'GET', 'path' => $path],
            'response' => ['headers' => ['Content-Type' => 'text/plain'], 'body' => 'requested ' . $path],
        ], $extra);
    }

    public function test_compiles_a_spanning_route_into_a_bucket(): void
    {
        $out = $this->compile([$this->doc('param-vite-fs', '/@fs/{path*}')]);

        self::assertSame(1, $out['schema']);
        self::assertArrayHasKey('@fs', $out['buckets']);
        $entry = $out['buckets']['@fs'][0];
        self::assertSame('param-vite-fs', $entry['id']);
        self::assertSame('^/@fs/(?P<path>.+)$', $entry['regex']);
        self::assertSame(['path'], $entry['captures']);
    }

    public function test_single_segment_placeholder_is_bounded_to_one_segment(): void
    {
        $out = $this->compile([$this->doc('param-wp', '/wp-content/plugins/{slug}/readme.txt')]);

        self::assertArrayHasKey('wp-content', $out['buckets']);
        $entry = $out['buckets']['wp-content'][0];
        self::assertSame(['slug'], $entry['captures']);

        // A one-segment capture must not span a slash.
        self::assertSame(1, preg_match('~' . $entry['regex'] . '~', '/wp-content/plugins/akismet/readme.txt', $m));
        self::assertSame('akismet', $m['slug']);
        self::assertSame(0, preg_match('~' . $entry['regex'] . '~', '/wp-content/plugins/a/b/readme.txt'));
    }

    public function test_root_param_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('unbucketable');
        $this->compile([$this->doc('param-root', '/{anything*}')]);
    }

    public function test_leading_placeholder_segment_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('unbucketable');
        $this->compile([$this->doc('param-root2', '/{x}/tail')]);
    }

    public function test_non_terminal_spanning_capture_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('last path segment');
        $this->compile([$this->doc('param-span', '/@fs/{path*}/x')]);
    }

    public function test_invalid_capture_name_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('capture name');
        $this->compile([$this->doc('param-badname', '/@fs/{1bad}')]);
    }

    public function test_path_with_no_placeholder_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('no {param}');
        $this->compile([$this->doc('param-static', '/@fs/static')]);
    }

    public function test_over_full_bucket_is_rejected(): void
    {
        $docs = [];
        for ($i = 0; $i <= 32; $i++) { // 33 entries, cap is 32
            $docs[] = $this->doc('over-' . $i, '/@fs/{p' . $i . '}');
        }
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('cap is 32');
        $this->compile($docs);
    }

    public function test_unknown_directive_is_rejected(): void
    {
        $doc = $this->doc('param-typo', '/@fs/{path*}');
        $doc['response']['body'] = 'x {{cannd.passwd}}';
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('unknown directive');
        $this->compile([$doc]);
    }

    public function test_fake_person_directive_passes_the_lint(): void
    {
        $doc = $this->doc('param-person', '/@fs/{path*}');
        $doc['response']['body'] = '{{fake.person.full:r0}} {{fake.person.username:r0}} {{fake.person.email:r0}}';
        $out = $this->compile([$doc]);
        self::assertArrayHasKey('@fs', $out['buckets']);
    }

    public function test_fake_person_unknown_subfield_is_rejected(): void
    {
        // fake.person.* is a CLOSED sub-field set (unlike a plain fake.NAME) — a mistyped
        // sub-field must fail the build, not silently render '' at runtime.
        $doc = $this->doc('param-person-typo', '/@fs/{path*}');
        $doc['response']['body'] = '{{fake.person.fulll:r0}}';
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('unknown fake.person field');
        $this->compile([$doc]);
    }

    public function test_duplicate_id_within_the_param_set_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Duplicate param template id');
        $this->compile([
            $this->doc('param-dup', '/@fs/{path*}'),
            $this->doc('param-dup', '/wp/{slug}'),
        ]);
    }

    public function test_id_colliding_with_the_attack_set_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('collides with an attack rule id');
        $this->compile([$this->doc('attack-lfi-unix', '/@fs/{path*}')], ['attack-lfi-unix']);
    }

    public function test_crlf_in_a_static_header_is_rejected(): void
    {
        $doc = $this->doc('param-crlf', '/@fs/{path*}');
        $doc['response']['headers'] = ['X-Bad' => "a\r\nInjected: 1"];
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('CR/LF/NUL');
        $this->compile([$doc]);
    }

    public function test_expect_marker_absent_from_empty_capture_render_is_rejected(): void
    {
        // An expect marker that only appears via a reflected capture would not survive the empty
        // render the build checks — target static text instead.
        $doc = $this->doc('param-expect', '/@fs/{path*}');
        $doc['response']['body'] = '// path: {{match.path}}';
        $doc['expect'] = ['/etc/passwd'];
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('expected marker');
        $this->compile([$doc]);
    }

    // --- the traversal-read behavior ---------------------------------------------------------

    public function test_compiles_a_traversal_read_behavior(): void
    {
        $out = $this->compile([$this->doc('param-tr', '/@fs/{path*}', [
            'behavior' => 'traversal-read',
            'traversal-read' => [
                'allow' => [
                    ['suffix' => 'etc/passwd', 'content' => ['headers' => ['Content-Type' => 'text/plain'], 'body' => '{{canned.passwd}}']],
                    ['basename' => 'wp-config.php', 'content' => ['body' => '<?php // fake']],
                ],
            ],
        ])]);

        $entry = $out['buckets']['@fs'][0];
        self::assertSame('traversal-read', $entry['behavior']);
        $allow = $entry['traversal-read']['allow'];
        self::assertCount(2, $allow);
        self::assertSame('etc/passwd', $allow[0]['suffix']);
        self::assertArrayNotHasKey('basename', $allow[0]);
        self::assertSame(200, $allow[0]['content']['status']); // status defaults to 200
        self::assertSame('wp-config.php', $allow[1]['basename']);
        self::assertArrayNotHasKey('suffix', $allow[1]);

        // The emitted entry (nested traversal-read arrays included) must be pure inert DATA — the
        // same gate a signed rules-update artifact passes before it is ever require()d.
        $php = "<?php\n\ndeclare(strict_types=1);\n\nreturn " . var_export($out, true) . ";\n";
        self::assertTrue((new PhpLiteralValidator())->isValid($php), 'compiled traversal-read entry must be a pure array literal');
    }

    public function test_traversal_read_empty_allow_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('at least one entry');
        $this->compile([$this->doc('param-tr-empty', '/@fs/{path*}', [
            'behavior' => 'traversal-read',
            'traversal-read' => ['allow' => []],
        ])]);
    }

    public function test_traversal_read_entry_missing_both_suffix_and_basename_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('exactly one');
        $this->compile([$this->doc('param-tr-neither', '/@fs/{path*}', [
            'behavior' => 'traversal-read',
            'traversal-read' => ['allow' => [['content' => ['body' => 'x']]]],
        ])]);
    }

    public function test_traversal_read_entry_with_both_suffix_and_basename_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('exactly one');
        $this->compile([$this->doc('param-tr-both', '/@fs/{path*}', [
            'behavior' => 'traversal-read',
            'traversal-read' => ['allow' => [['suffix' => '.env', 'basename' => 'x', 'content' => ['body' => 'x']]]],
        ])]);
    }

    public function test_traversal_read_entry_missing_content_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("needs a 'content'");
        $this->compile([$this->doc('param-tr-nocontent', '/@fs/{path*}', [
            'behavior' => 'traversal-read',
            'traversal-read' => ['allow' => [['suffix' => '.env']]],
        ])]);
    }

    public function test_traversal_read_bad_directive_in_content_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('unknown directive');
        $this->compile([$this->doc('param-tr-typo', '/@fs/{path*}', [
            'behavior' => 'traversal-read',
            'traversal-read' => ['allow' => [['suffix' => '.env', 'content' => ['body' => '{{cannd.passwd}}']]]],
        ])]);
    }

    public function test_traversal_read_bad_status_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('out of the 100-599');
        $this->compile([$this->doc('param-tr-status', '/@fs/{path*}', [
            'behavior' => 'traversal-read',
            'traversal-read' => ['allow' => [['suffix' => '.env', 'content' => ['body' => 'x', 'status' => 999]]]],
        ])]);
    }

    public function test_traversal_read_crlf_in_a_content_header_is_rejected(): void
    {
        // C8 at build time: a CR/LF/NUL in a static content header is a header-split vector.
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('CR/LF/NUL');
        $this->compile([$this->doc('param-tr-crlf', '/@fs/{path*}', [
            'behavior' => 'traversal-read',
            'traversal-read' => ['allow' => [['suffix' => '.env', 'content' => ['headers' => ['X-Bad' => "a\r\nInjected: 1"], 'body' => 'x']]]],
        ])]);
    }

    public function test_unknown_behavior_error_names_traversal_read(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('traversal-read');
        $this->compile([$this->doc('param-teleport', '/@fs/{path*}', ['behavior' => 'teleport'])]);
    }

    private function rmrf(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            is_dir($path) ? $this->rmrf($path) : @unlink($path);
        }
        @rmdir($dir);
    }
}
