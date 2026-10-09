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
        if ($ext === 'tar') {
            self::assertSame("ustar\0", substr($out['body'], 257, 6));
        } else {
            self::assertSame($magic, substr($out['body'], 0, strlen($magic)));
        }
        self::assertLessThanOrEqual(DecoyArchiveBuilder::DEFAULT_MAX_BYTES, strlen($out['body']));
    }

    public function test_seven_zip_is_the_chain_with_per_deploy_padding_and_stays_valid(): void
    {
        $out = (new DecoyArchiveBuilder())->build('7z', 'backup', self::SEED);
        self::assertNotNull($out);
        $body = $out['body'];
        self::assertGreaterThan(strlen(self::$chain), strlen($body));
        // Start-header CRC matches its 20 bytes, and the packed streams are untouched.
        self::assertSame(crc32(substr($body, 12, 20)) & 0xffffffff, unpack('V', substr($body, 8, 4))[1] & 0xffffffff);
        $h = unpack('Vlo', substr(self::$chain, 12, 4));
        self::assertSame(substr(self::$chain, 32, $h['lo']), substr($body, 32, $h['lo']));
        // The rewritten NextHeaderOffset must land on the original end header (its CRC still matches).
        $nh = unpack('Vlo/Vhi/Vsize/Vsizehi/Vcrc', substr($body, 12, 20));
        self::assertSame($nh['crc'] & 0xffffffff, crc32(substr($body, 32 + $nh['lo'], $nh['size'])) & 0xffffffff);
        self::assertSame(substr(self::$chain, 32 + $h['lo']), substr($body, -(strlen(self::$chain) - 32 - $h['lo'])));
    }

    public function test_every_extension_differs_in_length_across_deploys(): void
    {
        $b = new DecoyArchiveBuilder(null, true, function_exists('bzcompress'));
        foreach (DecoyArchiveName::EXTENSIONS as $ext) {
            if (!$b->supports($ext)) {
                continue;
            }
            $lengths = [];
            foreach ([11, 22, 33, 44] as $seed) {
                $lengths[strlen($b->build($ext, 'backup', $seed)['body'])] = true;
            }
            self::assertGreaterThanOrEqual(3, count($lengths), $ext . ' length must not be a shared constant');
        }
    }

    public function test_chain_survives_every_wrapper_intact(): void
    {
        $b = new DecoyArchiveBuilder(null, true, true);
        $seven = $b->build('7z', 'x', self::SEED)['body'];
        $tar = gzdecode($b->build('tar.gz', 'www', self::SEED)['body']);
        self::assertNotFalse(strpos($tar, $seven));
        self::assertNotFalse(strpos(gzdecode($b->build('gz', 'backup', self::SEED)['body']), "ustar\0"));
        self::assertNotFalse(strpos($b->build('zip', 'site', self::SEED)['body'], $seven));
        if (function_exists('bzdecompress')) {
            self::assertNotFalse(strpos(bzdecompress($b->build('bz2', 'backup', self::SEED)['body']), $seven));
        }
    }

    public function test_host_names_are_parsed_for_matching_only(): void
    {
        self::assertSame('shop.example.org', DecoyArchiveBuilder::hostName('Shop.Example.org:8443'));
        self::assertSame('', DecoyArchiveBuilder::hostName('10.0.0.5'));
        self::assertSame('', DecoyArchiveBuilder::hostName('[::1]:80'));
        self::assertSame('', DecoyArchiveBuilder::hostName('localhost'));
    }

    public function test_wp_config_uses_a_mysql_host_and_the_full_salt_set(): void
    {
        $zip = (new DecoyArchiveBuilder())->build('zip', 'backup', self::SEED)['body'];
        self::assertSame(1, preg_match("/define\\('DB_HOST', '(localhost|127\\.0\\.0\\.1|mysql|db|localhost:3306|mariadb)'\\)/", $zip));
        self::assertSame(8, preg_match_all("/define\\('(AUTH|SECURE_AUTH|LOGGED_IN|NONCE)_(KEY|SALT)'/", $zip));
        self::assertNotFalse(strpos($zip, "require_once ABSPATH . 'wp-settings.php';"));
    }

    public function test_a_failed_chain_load_is_retried_not_cached(): void
    {
        $dir = sys_get_temp_dir() . '/fpdecoy-retry-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $b = new DecoyArchiveBuilder($dir);
        self::assertNull($b->build('zip', 'backup', self::SEED));
        copy(__DIR__ . '/../../resources/decoy/chain.7z', $dir . '/chain.7z');
        copy(__DIR__ . '/../../resources/decoy/chain.json', $dir . '/chain.json');
        self::assertNotNull($b->build('zip', 'backup', self::SEED));
        unlink($dir . '/chain.7z');
        unlink($dir . '/chain.json');
        rmdir($dir);
    }

    public function test_outer_layer_is_deterministic_per_persona_and_differs_across_personas(): void
    {
        $b = new DecoyArchiveBuilder();
        $one = $b->build('zip', 'backup', self::SEED)['body'];
        self::assertSame($one, (new DecoyArchiveBuilder())->build('zip', 'backup', self::SEED)['body']);
        self::assertNotSame($one, $b->build('zip', 'backup', self::SEED + 1)['body']);
    }

    public function test_persona_files_are_present_and_carry_no_tarpit_wording(): void
    {
        $zip = (new DecoyArchiveBuilder())->build('zip', 'backup', self::SEED)['body'];
        foreach (['backup/backup.7z', 'backup/MANIFEST.sha256', 'backup/backup.log', 'backup/contents.txt', 'backup/RESTORE.txt', 'backup/wp-config.php'] as $name) {
            self::assertNotFalse(strpos($zip, $name), $name);
        }
        $seven = (new DecoyArchiveBuilder())->build('7z', 'x', self::SEED)['body'];
        self::assertNotFalse(strpos($zip, hash('sha256', $seven) . '  backup.7z'));
        foreach (['funnypot', 'honeypot', 'tarpit', 'decoy'] as $tell) {
            self::assertFalse(stripos(str_replace($seven, '', $zip), $tell), $tell);
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
