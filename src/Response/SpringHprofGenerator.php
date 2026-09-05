<?php

declare(strict_types=1);

namespace Funnypot\Core\Response;

use Funnypot\Core\Template\DirectiveRenderer;

/**
 * Writes a compact but structurally complete HotSpot HPROF (`JAVA PROFILE 1.0.2`) heap dump — the
 * bytes Spring Boot's `/actuator/heapdump` streams — whose only heap objects are rooted
 * `java.lang.String` instances carrying this deploy's persona datasource, AWS, admin and JWT
 * secrets. A heap analyser resolves every reference and reconstructs each string from its backing
 * byte array; `strings -a` recovers them directly.
 *
 * This is a closed writer for exactly one object graph, not a general HPROF serializer: the record
 * grammar follows OpenJDK's heapDumper.cpp (8-byte identifiers, big-endian u1/u2/u4/u8, one
 * HEAP_DUMP_SEGMENT, HEAP_DUMP_END at EOF). Every ID is allocated from a pinned schedule so a
 * refactor can never silently reshuffle the fixtures a test pins. Deliberately tiny: a real heap has
 * thousands of classes and objects — this one is built to parse and to bait extraction, not to pass
 * a size or histogram comparison against a live JVM.
 *
 * The header timestamp is the same seeded boot date the Spring logfile decoy prints, so the two
 * artifacts agree on when this host started. No wall clock, no I/O, no request data.
 */
final class SpringHprofGenerator implements BinaryBodyGenerator
{
    /**
     * The boot-date pick. Must stay byte-identical to the directive the Spring logfile route template
     * renders — the keyed pick makes both resolve to one date per render seed.
     */
    public const DATE_DIRECTIVE = '{{pick:spring-log-date:2026-04-14,2026-05-09,2026-06-21,2026-07-18,2026-08-24}}';

    /** Header instant per pickable date: that day at 08:12:04.112Z (the log's first line), epoch ms. */
    private const HEADER_MILLIS = [
        '2026-04-14' => 1776154324112,
        '2026-05-09' => 1778314324112,
        '2026-06-21' => 1782029524112,
        '2026-07-18' => 1784362324112,
        '2026-08-24' => 1787559124112,
    ];

    /**
     * The strings planted as rooted java.lang.String objects, in emission order. Persona fields
     * resolve through the renderer's closed {{persona.*}} set, so the heap discloses the same
     * datasource/AWS/admin/JWT identity every other Spring surface on this deploy does.
     */
    private const PAYLOADS = [
        'org.springframework.boot.autoconfigure.jdbc.DataSourceProperties',
        'com.zaxxer.hikari.HikariDataSource',
        'spring.datasource.url=jdbc:postgresql://{{persona.db.host}}:5432/{{persona.db.name}}',
        'spring.datasource.username={{persona.db.user}}',
        'spring.datasource.password={{persona.db.password}}',
        'AWS_ACCESS_KEY_ID={{persona.cloud.aws.accessKeyId}}',
        'AWS_SECRET_ACCESS_KEY={{persona.cloud.aws.secretKey}}',
        'AWS_REGION={{persona.cloud.aws.region}}',
        'spring.security.user.name={{persona.user.admin.username}}',
        'spring.security.user.password={{persona.user.admin.password}}',
        'jwt.signing.secret={{persona.secret.jwt}}',
        'eureka.client.serviceUrl.defaultZone=http://{{persona.user.admin.username}}:{{persona.user.admin.password}}@discovery.internal:8761/eureka/',
    ];

    /** UTF8 string-table entries, in ID order from ID_UTF8_BASE: two class names, then String's fields. */
    private const NAMES = ['java/lang/Object', 'java/lang/String', 'value', 'coder', 'hash', 'hashIsZero'];

    // Top-level record tags.
    private const TAG_UTF8 = 0x01;
    private const TAG_LOAD_CLASS = 0x02;
    private const TAG_TRACE = 0x05;
    private const TAG_HEAP_DUMP_SEGMENT = 0x1c;
    private const TAG_HEAP_DUMP_END = 0x2c;

    // Heap-segment sub-record tags.
    private const GC_ROOT_UNKNOWN = 0xff;
    private const GC_ROOT_STICKY_CLASS = 0x05;
    private const GC_CLASS_DUMP = 0x20;
    private const GC_INSTANCE_DUMP = 0x21;
    private const GC_PRIM_ARRAY_DUMP = 0x23;

    // HPROF basic types.
    private const T_OBJECT = 2;
    private const T_BOOLEAN = 4;
    private const T_BYTE = 8;
    private const T_INT = 10;

    /** Identifier size the header declares; every ID/reference below is written at this width. */
    private const ID_SIZE = 8;

    // Pinned ID schedule. UTF8 IDs follow NAMES; payload i uses array 0x2000+2i and String 0x2001+2i.
    private const ID_UTF8_BASE = 0x0101;
    private const ID_CLASS_OBJECT = 0x1001;
    private const ID_CLASS_STRING = 0x1002;
    private const ID_PAYLOAD_BASE = 0x2000;

    /** Java 17 compact-string layout: value (byte[]), coder (byte), hash (int), hashIsZero (boolean). */
    private const STRING_INSTANCE_SIZE = 24;
    private const OBJECT_INSTANCE_SIZE = 16;
    private const CODER_LATIN1 = 0;

    private const MAX_STRING_BYTES = 1024;
    private const MAX_OUTPUT_BYTES = 65536;

    public function generate(DirectiveRenderer $renderer, int $seed): ?string
    {
        // The u8 timestamp and the 32-bit hash wrap both rely on native 64-bit ints.
        if (PHP_INT_SIZE < 8) {
            return null;
        }

        $date = $renderer->render(self::DATE_DIRECTIVE, [], $seed);
        if (!isset(self::HEADER_MILLIS[$date])) {
            return null;
        }

        $strings = [];
        foreach (self::PAYLOADS as $template) {
            // An empty persona field would plant a truncated credential; decline rather than mislead.
            if (preg_match_all('/\{\{\s*([^}]+?)\s*\}\}/', $template, $directives)) {
                foreach ($directives[0] as $directive) {
                    if ($renderer->render($directive, [], $seed) === '') {
                        return null;
                    }
                }
            }
            $rendered = $renderer->render($template, [], $seed);
            if (!self::isPlantable($rendered)) {
                return null;
            }
            $strings[] = $rendered;
        }

        $out = "JAVA PROFILE 1.0.2\0" . self::u4(self::ID_SIZE) . self::u8(self::HEADER_MILLIS[$date]);
        foreach (self::NAMES as $i => $name) {
            $out .= self::record(self::TAG_UTF8, self::id(self::ID_UTF8_BASE + $i) . $name);
        }
        $out .= self::record(self::TAG_LOAD_CLASS, self::u4(1) . self::id(self::ID_CLASS_OBJECT) . self::u4(1) . self::id(self::ID_UTF8_BASE));
        $out .= self::record(self::TAG_LOAD_CLASS, self::u4(2) . self::id(self::ID_CLASS_STRING) . self::u4(1) . self::id(self::ID_UTF8_BASE + 1));
        // One empty stack trace (serial 1) every class/instance/array below points at.
        $out .= self::record(self::TAG_TRACE, self::u4(1) . self::u4(0) . self::u4(0));
        $out .= self::record(self::TAG_HEAP_DUMP_SEGMENT, self::heapSegment($strings));
        $out .= self::record(self::TAG_HEAP_DUMP_END, '');

        if (strlen($out) > self::MAX_OUTPUT_BYTES) {
            return null;
        }

        return $out;
    }

    /**
     * The single heap segment: both classes rooted as sticky, their class dumps, then per planted
     * string a root, its backing byte array and the String instance referencing it.
     *
     * @param string[] $strings
     */
    private static function heapSegment(array $strings): string
    {
        $seg = self::u1(self::GC_ROOT_STICKY_CLASS) . self::id(self::ID_CLASS_OBJECT)
            . self::u1(self::GC_ROOT_STICKY_CLASS) . self::id(self::ID_CLASS_STRING);

        $seg .= self::classDump(self::ID_CLASS_OBJECT, 0, self::OBJECT_INSTANCE_SIZE, []);
        $seg .= self::classDump(self::ID_CLASS_STRING, self::ID_CLASS_OBJECT, self::STRING_INSTANCE_SIZE, [
            [self::ID_UTF8_BASE + 2, self::T_OBJECT],
            [self::ID_UTF8_BASE + 3, self::T_BYTE],
            [self::ID_UTF8_BASE + 4, self::T_INT],
            [self::ID_UTF8_BASE + 5, self::T_BOOLEAN],
        ]);

        foreach (array_values($strings) as $i => $s) {
            $arrayId = self::ID_PAYLOAD_BASE + 2 * $i;
            $stringId = $arrayId + 1;
            $hash = self::javaHash($s);

            $seg .= self::u1(self::GC_ROOT_UNKNOWN) . self::id($stringId);
            $seg .= self::u1(self::GC_PRIM_ARRAY_DUMP) . self::id($arrayId) . self::u4(1)
                . self::u4(strlen($s)) . self::u1(self::T_BYTE) . $s;
            // Field values in declared order: value ref, coder, hash, hashIsZero (Object adds none).
            $fields = self::id($arrayId) . self::u1(self::CODER_LATIN1) . self::u4($hash) . self::u1($hash === 0 ? 1 : 0);
            $seg .= self::u1(self::GC_INSTANCE_DUMP) . self::id($stringId) . self::u4(1)
                . self::id(self::ID_CLASS_STRING) . self::u4(strlen($fields)) . $fields;
        }

        return $seg;
    }

    /**
     * CLASS_DUMP with no loader/signers/protection domain, an empty constant pool and no statics.
     *
     * @param array<int,array{0:int,1:int}> $fields [nameId, basicType] in declared order
     */
    private static function classDump(int $classId, int $superId, int $instanceSize, array $fields): string
    {
        $out = self::u1(self::GC_CLASS_DUMP) . self::id($classId) . self::u4(1) . self::id($superId)
            . self::id(0) . self::id(0) . self::id(0) . self::id(0) . self::id(0)
            . self::u4($instanceSize) . self::u2(0) . self::u2(0) . self::u2(count($fields));
        foreach ($fields as $field) {
            $out .= self::id($field[0]) . self::u1($field[1]);
        }

        return $out;
    }

    /** Printable ASCII only, bounded — the byte class a LATIN1-coded Java String can hold verbatim. */
    private static function isPlantable(string $s): bool
    {
        return $s !== '' && strlen($s) <= self::MAX_STRING_BYTES && preg_match('/^[\x20-\x7e]+$/', $s) === 1;
    }

    /** java.lang.String#hashCode over LATIN1 bytes (h = 31*h + b, 32-bit wrap), as its unsigned u4 image. */
    private static function javaHash(string $s): int
    {
        $h = 0;
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $h = ($h * 31 + ord($s[$i])) & 0xffffffff;
        }

        return $h;
    }

    /** One top-level record: tag, zero time offset, exact body length, body. */
    private static function record(int $tag, string $body): string
    {
        return self::u1($tag) . self::u4(0) . self::u4(strlen($body)) . $body;
    }

    private static function u1(int $v): string
    {
        return chr($v & 0xff);
    }

    private static function u2(int $v): string
    {
        return pack('n', $v);
    }

    private static function u4(int $v): string
    {
        return pack('N', $v);
    }

    private static function u8(int $v): string
    {
        return pack('N2', ($v >> 32) & 0xffffffff, $v & 0xffffffff);
    }

    private static function id(int $v): string
    {
        return self::u8($v);
    }
}
