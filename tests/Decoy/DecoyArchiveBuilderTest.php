<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Decoy;

use Funnypot\Core\Decoy\DecoyArchiveBuilder;
use Funnypot\Core\Decoy\DecoyArchiveName;
use PHPUnit\Framework\TestCase;

final class DecoyArchiveBuilderTest extends TestCase
{
    private const SEED = 424242;

    /** @var string */
    private static $chain;

    public static function setUpBeforeClass(): void
    {
        self::$chain = (string) file_get_contents(__DIR__ . '/../../resources/decoy/chain.7z');
    }

    /**
     * @return array<string,array{0:string,1:string,2:string}>
     */
    public static function formats(): array
    {
        return [
            '7z' => ['7z', "7z\xBC\xAF\x27\x1C", 'application/x-7z-compressed'],
            'zip' => ['zip', "PK\x03\x04", 'application/zip'],
            'tar' => ['tar', '', 'application/x-tar'],
            'tar.gz' => ['tar.gz', "\x1f\x8b", 'application/gzip'],
            'tgz' => ['tgz', "\x1f\x8b", 'application/gzip'],
            'gz' => ['gz', "\x1f\x8b", 'application/gzip'],
            'tar.bz2' => ['tar.bz2', 'BZh', 'application/x-bzip2'],
            'tbz2' => ['tbz2', 'BZh', 'application/x-bzip2'],
            'bz2' => ['bz2', 'BZh', 'application/x-bzip2'],
        ];
    }

    /**
     * @dataProvider formats
     */
    public function test_magic_bytes_and_content_type_match_the_extension(string $ext, string $magic, string $type): void
    {
        $b = new DecoyArchiveBuilder(null, true, true);
        $out = $b->build($ext, 'backup', self::SEED);
        if ($out === null && !function_exists('bzcompress') && strpos($ext, 'bz') !== false) {
            self::markTestSkipped('ext-bz2 not loaded');
        }
        self::assertNotNull($out);
        self::assertSame($type, $out['type']);
        self::assertSame('backup.' . $ext, $out['filename']);
        if ($ext === 'tar') {
            self::assertSame("ustar\0", substr($out['body'], 257, 6));
        } else {
            self::assertSame($magic, substr($out['body'], 0, strlen($magic)));
        }
        self::assertLessThanOrEqual(DecoyArchiveBuilder::DEFAULT_MAX_BYTES, strlen($out['body']));
    }

    public function test_seven_zip_is_the_chain_verbatim(): void
    {
        $out = (new DecoyArchiveBuilder())->build('7z', 'backup', self::SEED);
        self::assertNotNull($out);
        self::assertSame(self::$chain, $out['body']);
    }

    public function test_chain_survives_every_wrapper_intact(): void
    {
        $b = new DecoyArchiveBuilder(null, true, true);
        self::assertSame(self::$chain, gzdecode($b->build('gz', 'backup', self::SEED)['body']));
        $tar = gzdecode($b->build('tar.gz', 'www', self::SEED)['body']);
        self::assertNotFalse(strpos($tar, self::$chain));
        self::assertNotFalse(strpos($b->build('zip', 'site', self::SEED)['body'], self::$chain));
        if (function_exists('bzdecompress')) {
            self::assertSame(self::$chain, bzdecompress($b->build('bz2', 'backup', self::SEED)['body']));
        }
    }

    public function test_outer_layer_is_deterministic_per_persona_and_differs_across_personas(): void
    {
        $b = new DecoyArchiveBuilder();
        $one = $b->build('zip', 'backup', self::SEED)['body'];
        self::assertSame($one, $b->build('zip', 'backup', self::SEED)['body']);
        self::assertNotSame($one, $b->build('zip', 'backup', self::SEED + 1)['body']);
    }

    public function test_persona_files_are_present_and_carry_no_tarpit_wording(): void
    {
        $zip = (new DecoyArchiveBuilder())->build('zip', 'backup', self::SEED)['body'];
        foreach (['backup/backup.7z', 'backup/MANIFEST.sha256', 'backup/backup.log', 'backup/RESTORE.txt', 'backup/wp-config.php'] as $name) {
            self::assertNotFalse(strpos($zip, $name), $name);
        }
        self::assertNotFalse(strpos($zip, hash('sha256', self::$chain) . '  backup.7z'));
        foreach (['funnypot', 'honeypot', 'tarpit', 'decoy'] as $tell) {
            self::assertFalse(stripos(str_replace(self::$chain, '', $zip), $tell), $tell);
        }
    }

    public function test_unwritable_formats_decline(): void
    {
        $b = new DecoyArchiveBuilder(null, false, false);
        foreach (['tar.gz', 'tgz', 'gz', 'tar.bz2', 'tbz2', 'bz2'] as $ext) {
            self::assertFalse($b->supports($ext), $ext);
            self::assertNull($b->build($ext, 'backup', self::SEED), $ext);
        }
        self::assertNotNull($b->build('zip', 'backup', self::SEED));
        self::assertFalse($b->supports('rar'));
    }

    public function test_missing_or_altered_chain_declines(): void
    {
        $dir = sys_get_temp_dir() . '/fpdecoy-' . bin2hex(random_bytes(4));
        mkdir($dir);
        self::assertNull((new DecoyArchiveBuilder($dir))->build('zip', 'backup', self::SEED));

        file_put_contents($dir . '/chain.7z', self::$chain . 'x');
        copy(__DIR__ . '/../../resources/decoy/chain.json', $dir . '/chain.json');
        self::assertNull((new DecoyArchiveBuilder($dir))->build('7z', 'backup', self::SEED));

        unlink($dir . '/chain.7z');
        unlink($dir . '/chain.json');
        rmdir($dir);
    }

    public function test_over_cap_declines(): void
    {
        self::assertNull((new DecoyArchiveBuilder())->build('zip', 'backup', self::SEED, 1000));
    }

    public function test_every_canonical_extension_has_a_type(): void
    {
        $b = new DecoyArchiveBuilder(null, true, true);
        foreach (DecoyArchiveName::EXTENSIONS as $ext) {
            self::assertTrue($b->supports($ext), $ext);
        }
    }
}
