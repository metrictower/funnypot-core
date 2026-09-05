<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use DateTimeImmutable;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Response\BinaryBodyGeneratorRegistry;
use Funnypot\Core\Response\SpringHprofGenerator;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * The spring_hprof_v1 byte format, parsed by an INDEPENDENT strict cursor parser (not the writer's
 * own helpers): exact record consumption with no overrun or trailing bytes, the pinned ID schedule,
 * class/field layout, reference integrity, Java-compatible String hashes, and every planted String
 * reconstructed from its byte array and equal to the same seed's PersonaIdentity. Also the bounds
 * (< 4 KB across the persona matrix), determinism + pinned goldens, the logfile-coherent header
 * time, a `strings`-style recovery of every secret, and — because both fingerprint gates skip bin
 * bodies — a FingerprintGuard scan over the rendered bytes (nothing else ever scans them).
 */
final class SpringHprofGeneratorTest extends TestCase
{
    private const MAGIC = 'JAVA PROFILE 1.0.2';

    private const DATES = ['2026-04-14', '2026-05-09', '2026-06-21', '2026-07-18', '2026-08-24'];

    // HPROF tags (OpenJDK heapDumper.cpp), spelled out here so the parser is not the writer's constants.
    private const UTF8 = 0x01;
    private const LOAD_CLASS = 0x02;
    private const TRACE = 0x05;
    private const HEAP_DUMP_SEGMENT = 0x1c;
    private const HEAP_DUMP_END = 0x2c;

    private function generate(?int $personaSeed, int $renderSeed): string
    {
        $bytes = (new SpringHprofGenerator())->generate(new DirectiveRenderer($personaSeed), $renderSeed);
        self::assertNotNull($bytes, 'the generator must not decline for a real renderer');

        return $bytes;
    }

    /**
     * Strict cursor parse of the whole file. Every assertion here is a format-grammar fact.
     *
     * @return array<string,mixed>
     */
    private function parse(string $b): array
    {
        $n = strlen($b);
        $p = 0;
        $take = static function (int $k) use ($b, $n, &$p): string {
            self::assertLessThanOrEqual($n, $p + $k, "a read of {$k} bytes at offset {$p} overruns the {$n}-byte file");
            $s = substr($b, $p, $k);
            $p += $k;

            return $s;
        };
        $u1 = static function () use ($take): int { return ord($take(1)); };
        $u2 = static function () use ($take): int { return unpack('n', $take(2))[1]; };
        $u4 = static function () use ($take): int { return unpack('N', $take(4))[1]; };
        $u8 = static function () use ($take): int {
            $w = unpack('N2', $take(8));

            return ($w[1] << 32) | $w[2];
        };

        $nul = strpos($b, "\0");
        self::assertSame(strlen(self::MAGIC), $nul, 'header magic must be NUL-terminated exactly after the version string');
        self::assertSame(self::MAGIC, $take($nul));
        $take(1);
        self::assertSame(8, $u4(), 'identifier size');
        $out = [
            'ts' => $u8(), 'records' => [], 'utf8' => [], 'classes' => [], 'traces' => [],
            'sticky' => [], 'roots' => [], 'classDumps' => [], 'instances' => [], 'arrays' => [],
        ];

        while ($p < $n) {
            $tag = $u1();
            self::assertSame(0, $u4(), 'record time offset');
            $len = $u4();
            $end = $p + $len;
            self::assertLessThanOrEqual($n, $end, sprintf('record 0x%02x declares a length past EOF', $tag));
            $out['records'][] = $tag;
            switch ($tag) {
                case self::UTF8:
                    $id = $u8();
                    self::assertArrayNotHasKey($id, $out['utf8'], 'duplicate UTF8 id');
                    $out['utf8'][$id] = $take($len - 8);
                    break;
                case self::LOAD_CLASS:
                    self::assertSame(24, $len);
                    $serial = $u4();
                    $out['classes'][$serial] = ['obj' => $u8(), 'st' => $u4(), 'name' => $u8()];
                    break;
                case self::TRACE:
                    self::assertSame(12, $len);
                    $serial = $u4();
                    $out['traces'][$serial] = ['thread' => $u4(), 'frames' => $u4()];
                    break;
                case self::HEAP_DUMP_SEGMENT:
                    while ($p < $end) {
                        $sub = $u1();
                        switch ($sub) {
                            case 0xff:
                                $out['roots'][] = $u8();
                                break;
                            case 0x05:
                                $out['sticky'][] = $u8();
                                break;
                            case 0x20:
                                $cid = $u8();
                                $dump = ['st' => $u4(), 'super' => $u8(), 'loader' => $u8(), 'signers' => $u8(), 'pd' => $u8(), 'r1' => $u8(), 'r2' => $u8(), 'size' => $u4()];
                                self::assertSame(0, $u2(), 'constant pool size');
                                self::assertSame(0, $u2(), 'static field count');
                                $nf = $u2();
                                $dump['fields'] = [];
                                for ($i = 0; $i < $nf; $i++) {
                                    $dump['fields'][] = [$u8(), $u1()];
                                }
                                self::assertArrayNotHasKey($cid, $out['classDumps'], 'duplicate class dump');
                                $out['classDumps'][$cid] = $dump;
                                break;
                            case 0x21:
                                $oid = $u8();
                                $inst = ['st' => $u4(), 'class' => $u8()];
                                $inst['data'] = $take($u4());
                                self::assertArrayNotHasKey($oid, $out['instances'], 'duplicate instance id');
                                $out['instances'][$oid] = $inst;
                                break;
                            case 0x23:
                                $aid = $u8();
                                $arr = ['st' => $u4()];
                                $count = $u4();
                                self::assertSame(8, $u1(), 'primitive array element type must be byte');
                                $arr['data'] = $take($count);
                                self::assertArrayNotHasKey($aid, $out['arrays'], 'duplicate array id');
                                $out['arrays'][$aid] = $arr;
                                break;
                            default:
                                self::fail(sprintf('unknown heap sub-record tag 0x%02x at offset %d', $sub, $p - 1));
                        }
                    }
                    break;
                case self::HEAP_DUMP_END:
                    self::assertSame(0, $len, 'HEAP_DUMP_END carries no body');
                    self::assertSame($n, $p, 'HEAP_DUMP_END must be the last record — no trailing bytes');
                    break;
                default:
                    self::fail(sprintf('unknown record tag 0x%02x at offset %d', $tag, $p - 9));
            }
            self::assertSame($end, $p, sprintf('record 0x%02x must be consumed exactly to its declared length', $tag));
        }
        self::assertSame($n, $p, 'the whole file must be consumed');

        return $out;
    }

    /** What the same identity seed plants, derived from PersonaIdentity — never from the generator. @return string[] */
    private function expectedStrings(int $identitySeed): array
    {
        $persona = PersonaIdentity::fromSeed($identitySeed);
        $f = static function (string $path) use ($persona): string {
            return (string) $persona->field($path);
        };

        return [
            'org.springframework.boot.autoconfigure.jdbc.DataSourceProperties',
            'com.zaxxer.hikari.HikariDataSource',
            'spring.datasource.url=jdbc:postgresql://' . $f('db.host') . ':5432/' . $f('db.name'),
            'spring.datasource.username=' . $f('db.user'),
            'spring.datasource.password=' . $f('db.password'),
            'AWS_ACCESS_KEY_ID=' . $f('cloud.aws.accessKeyId'),
            'AWS_SECRET_ACCESS_KEY=' . $f('cloud.aws.secretKey'),
            'AWS_REGION=' . $f('cloud.aws.region'),
            'spring.security.user.name=' . $f('user.admin.username'),
            'spring.security.user.password=' . $f('user.admin.password'),
            'jwt.signing.secret=' . $f('secret.jwt'),
            'eureka.client.serviceUrl.defaultZone=http://' . $f('user.admin.username') . ':' . $f('user.admin.password') . '@discovery.internal:8761/eureka/',
        ];
    }

    /** java.lang.String#hashCode over LATIN1 bytes, computed independently, as its unsigned u4 image. */
    private static function javaHash(string $s): int
    {
        $h = 0;
        foreach (str_split($s) as $c) {
            $h = ($h * 31 + ord($c)) & 0xffffffff;
        }

        return $h;
    }

    /** @return string[] printable runs of 4+ bytes — what `strings -a` prints */
    private static function strings(string $bytes): array
    {
        preg_match_all('/[\x20-\x7e]{4,}/', $bytes, $m);

        return $m[0];
    }

    /**
     * Full structural + schedule check of one dump against its expected strings.
     *
     * @param string[] $expected
     */
    private function assertWellFormed(string $bytes, array $expected, string $where): void
    {
        $d = $this->parse($bytes);

        self::assertSame(
            [self::UTF8, self::UTF8, self::UTF8, self::UTF8, self::UTF8, self::UTF8, self::LOAD_CLASS, self::LOAD_CLASS, self::TRACE, self::HEAP_DUMP_SEGMENT, self::HEAP_DUMP_END],
            $d['records'],
            "{$where}: top-level record sequence"
        );
        self::assertSame([
            0x0101 => 'java/lang/Object', 0x0102 => 'java/lang/String',
            0x0103 => 'value', 0x0104 => 'coder', 0x0105 => 'hash', 0x0106 => 'hashIsZero',
        ], $d['utf8'], "{$where}: UTF8 table and pinned ids");
        self::assertSame([
            1 => ['obj' => 0x1001, 'st' => 1, 'name' => 0x0101],
            2 => ['obj' => 0x1002, 'st' => 1, 'name' => 0x0102],
        ], $d['classes'], "{$where}: LOAD_CLASS records");
        self::assertSame([1 => ['thread' => 0, 'frames' => 0]], $d['traces'], "{$where}: one empty trace at serial 1");
        self::assertSame([0x1001, 0x1002], $d['sticky'], "{$where}: both classes are sticky roots");

        $object = $d['classDumps'][0x1001] ?? null;
        self::assertNotNull($object, "{$where}: Object class dump");
        self::assertSame(['st' => 1, 'super' => 0, 'loader' => 0, 'signers' => 0, 'pd' => 0, 'r1' => 0, 'r2' => 0, 'size' => 16, 'fields' => []], $object);
        $string = $d['classDumps'][0x1002] ?? null;
        self::assertNotNull($string, "{$where}: String class dump");
        self::assertSame(
            ['st' => 1, 'super' => 0x1001, 'loader' => 0, 'signers' => 0, 'pd' => 0, 'r1' => 0, 'r2' => 0, 'size' => 24, 'fields' => [[0x0103, 2], [0x0104, 8], [0x0105, 10], [0x0106, 4]]],
            $string,
            "{$where}: Java 17 String layout — value:object, coder:byte, hash:int, hashIsZero:boolean"
        );
        self::assertCount(2, $d['classDumps']);

        // Payload i: array 0x2000+2i, String 0x2001+2i; one ROOT_UNKNOWN per String, in order.
        $count = count($expected);
        self::assertCount($count, $d['instances'], "{$where}: one String per planted value");
        self::assertCount($count, $d['arrays'], "{$where}: one byte[] per planted value");
        self::assertCount($count, $d['roots']);
        $reconstructed = [];
        foreach ($expected as $i => $s) {
            $arrayId = 0x2000 + 2 * $i;
            $stringId = $arrayId + 1;
            self::assertSame($stringId, $d['roots'][$i], "{$where}: root {$i} is its String object");
            $arr = $d['arrays'][$arrayId] ?? null;
            self::assertNotNull($arr, "{$where}: array id for payload {$i}");
            self::assertSame(1, $arr['st']);
            $inst = $d['instances'][$stringId] ?? null;
            self::assertNotNull($inst, "{$where}: String id for payload {$i}");
            self::assertSame(1, $inst['st']);
            self::assertSame(0x1002, $inst['class'], "{$where}: instance {$i} is a java.lang.String");
            self::assertSame(14, strlen($inst['data']), "{$where}: instance data is exactly the four declared fields (8+1+4+1)");
            $f = unpack('N2ref/Ccoder/Nhash/Czero', $inst['data']);
            self::assertSame($arrayId, ($f['ref1'] << 32) | $f['ref2'], "{$where}: value points at its own byte[]");
            self::assertSame(0, $f['coder'], "{$where}: LATIN1 coder");
            self::assertSame(self::javaHash($arr['data']), $f['hash'], "{$where}: Java String hash of the bytes");
            self::assertSame($f['hash'] === 0 ? 1 : 0, $f['zero'], "{$where}: hashIsZero flag");
            $reconstructed[] = $arr['data'];
        }
        self::assertSame($expected, $reconstructed, "{$where}: every planted String reconstructs to the same seed's persona value");

        // Reference integrity + global ID uniqueness (non-zero, disjoint across every ID space).
        $ids = array_merge(array_keys($d['utf8']), array_keys($d['classDumps']), array_keys($d['arrays']), array_keys($d['instances']));
        self::assertNotContains(0, $ids, "{$where}: no zero id");
        self::assertSame(count($ids), count(array_unique($ids)), "{$where}: ids are globally unique");
        foreach ($d['classes'] as $c) {
            self::assertArrayHasKey($c['obj'], $d['classDumps'], "{$where}: loaded class has a dump");
            self::assertArrayHasKey($c['name'], $d['utf8'], "{$where}: class name resolves");
        }
        foreach ($d['classDumps'] as $cid => $dump) {
            if ($dump['super'] !== 0) {
                self::assertArrayHasKey($dump['super'], $d['classDumps'], "{$where}: superclass resolves");
            }
            foreach ($dump['fields'] as $field) {
                self::assertArrayHasKey($field[0], $d['utf8'], "{$where}: field name resolves");
            }
            self::assertContains($cid, $d['sticky'], "{$where}: every class is rooted");
        }
        foreach ($d['roots'] as $root) {
            self::assertArrayHasKey($root, $d['instances'], "{$where}: every root is an emitted object");
        }
        self::assertContains($d['ts'], array_map(static function (string $date): int {
            return (int) (new DateTimeImmutable($date . 'T08:12:04.112Z'))->format('Uv');
        }, self::DATES), "{$where}: header time is one of the boot instants");
    }

    public function test_structure_parses_strictly_against_the_pinned_schedule(): void
    {
        $this->assertWellFormed($this->generate(12345, 7), $this->expectedStrings(12345), 'persona 12345 / seed 7');
        // No persona seed: identity folds to the render seed.
        $this->assertWellFormed($this->generate(null, 3), $this->expectedStrings(3), 'seed 3');
    }

    public function test_persona_matrix_is_coherent_bounded_and_fingerprint_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $exemplars = ['example.com', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG', 'changeme', 'password123', 'secret123', 'hunter2', '{{'];
        $seeds = range(0, 60);
        foreach (['alpha', 'bravo', 'charlie', 'delta', 'echo'] as $salt) {
            $seeds[] = PersonaIdentity::seedFromMaterial($salt);
        }
        foreach ($seeds as $i => $personaSeed) {
            $renderSeed = ($i * 7919) % 1000;
            $bytes = $this->generate($personaSeed, $renderSeed);
            $where = "persona {$personaSeed} / seed {$renderSeed}";
            self::assertGreaterThan(0, strlen($bytes));
            self::assertLessThan(4096, strlen($bytes), "{$where}: bounded artifact");
            $this->assertWellFormed($bytes, $this->expectedStrings($personaSeed), $where);
            self::assertSame([], $guard->scan($bytes), "{$where}: rendered HPROF bytes must be fingerprint-clean");
            foreach ($exemplars as $bad) {
                self::assertStringNotContainsString($bad, $bytes, "{$where}: no literal example/real secret");
            }
            // Each planted secret appears in the byte stream as a printable run `strings -a` prints.
            $runs = self::strings($bytes);
            foreach ($this->expectedStrings($personaSeed) as $secret) {
                $found = false;
                foreach ($runs as $run) {
                    if (strpos($run, $secret) !== false) {
                        $found = true;
                        break;
                    }
                }
                self::assertTrue($found, "{$where}: strings -a must recover '{$secret}'");
            }
        }
    }

    public function test_header_time_is_the_logfile_boot_date_for_the_same_render_seed(): void
    {
        $renderer = new DirectiveRenderer();
        $seen = [];
        for ($seed = 0; $seed <= 200; $seed++) {
            $date = $renderer->render(SpringHprofGenerator::DATE_DIRECTIVE, [], $seed);
            self::assertContains($date, self::DATES, "seed {$seed}: the pick stays inside the closed date table");
            $expected = (int) (new DateTimeImmutable($date . 'T08:12:04.112Z'))->format('Uv');
            $bytes = $this->generate(null, $seed);
            $w = unpack('N2', substr($bytes, strlen(self::MAGIC) + 1 + 4, 8));
            self::assertSame($expected, ($w[1] << 32) | $w[2], "seed {$seed}: header ms must be {$date} 08:12:04.112Z");
            $seen[$date] = true;
        }
        self::assertCount(count(self::DATES), $seen, 'the sweep exercises every table entry');
    }

    public function test_render_seed_moves_the_date_but_never_the_persona(): void
    {
        // With a deploy persona seed wired, the identity is per-deploy: two attackers (two render
        // seeds) see the same credentials. The boot date rides the render seed — a documented tell.
        $a = $this->parse($this->generate(777, 1));
        $b = $this->parse($this->generate(777, 2));
        $strings = static function (array $d): array {
            return array_values(array_map(static function (array $arr): string { return $arr['data']; }, $d['arrays']));
        };
        self::assertSame($strings($a), $strings($b));
        self::assertSame($this->expectedStrings(777), $strings($a));
    }

    public function test_same_inputs_are_byte_identical_and_goldens_are_pinned(): void
    {
        self::assertSame($this->generate(12345, 7), $this->generate(12345, 7));
        $goldens = [
            [null, 0, 1929, '3c06da674b3f112fd7e7ef4fe9f425f00c3275001b1923bce51c97439e73a317'],
            [12345, 7, 1915, 'caa9e576c2f2d2ae4530899002315fee8403b7ac5fe247003a46417114f5c5b1'],
            [PersonaIdentity::seedFromMaterial('golden-a'), 42, 1918, '9ed23af995a61e7d7f52cc0b4cc5113c083baad601ae278cd94b5514c2d0b613'],
        ];
        foreach ($goldens as [$personaSeed, $renderSeed, $len, $sha]) {
            $bytes = $this->generate($personaSeed, $renderSeed);
            self::assertSame($len, strlen($bytes), "golden length for persona " . var_export($personaSeed, true) . " / seed {$renderSeed}");
            self::assertSame($sha, hash('sha256', $bytes), "golden sha256 for persona " . var_export($personaSeed, true) . " / seed {$renderSeed}");
        }
    }

    public function test_java_string_hash_matches_known_jvm_vectors(): void
    {
        $m = new ReflectionMethod(SpringHprofGenerator::class, 'javaHash');
        $m->setAccessible(true);
        self::assertSame(0, $m->invoke(null, ''));
        self::assertSame(99162322, $m->invoke(null, 'hello'));
        // "polygenelubricants".hashCode() == Integer.MIN_VALUE — the classic wrap vector, as unsigned u4.
        self::assertSame(0x80000000, $m->invoke(null, 'polygenelubricants'));
        self::assertSame(self::javaHash('spring.datasource.password=x'), $m->invoke(null, 'spring.datasource.password=x'));
    }

    public function test_plantable_guard_rejects_empty_control_non_ascii_and_oversize(): void
    {
        $m = new ReflectionMethod(SpringHprofGenerator::class, 'isPlantable');
        $m->setAccessible(true);
        self::assertTrue($m->invoke(null, 'abc'));
        self::assertTrue($m->invoke(null, str_repeat('a', 1024)));
        self::assertFalse($m->invoke(null, ''));
        self::assertFalse($m->invoke(null, "a\x00b"), 'NUL');
        self::assertFalse($m->invoke(null, "a\nb"), 'control byte');
        self::assertFalse($m->invoke(null, "caf\xc3\xa9"), 'non-ASCII');
        self::assertFalse($m->invoke(null, "\x7f"), 'DEL');
        self::assertFalse($m->invoke(null, str_repeat('a', 1025)), 'over 1024 bytes');
    }

    public function test_registry_default_resolves_the_generator_by_its_closed_id(): void
    {
        $registry = BinaryBodyGeneratorRegistry::default();
        self::assertInstanceOf(SpringHprofGenerator::class, $registry->find(BinaryBodyGeneratorRegistry::SPRING_HPROF_V1));
        self::assertSame('spring_hprof_v1', BinaryBodyGeneratorRegistry::SPRING_HPROF_V1);
        self::assertNull($registry->find('spring_hprof_v2'));
        self::assertNull($registry->find(''));
    }
}
