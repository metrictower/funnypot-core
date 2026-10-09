<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Decoy;

use Funnypot\Core\Decoy\DecoyArchiveName;
use PHPUnit\Framework\TestCase;

final class DecoyArchiveNameTest extends TestCase
{
    /**
     * @return array<string,array{0:string,1:string,2:string}>
     */
    public static function backupNames(): array
    {
        return [
            'plain zip' => ['/backup.zip', 'zip', 'backup'],
            'digit suffix' => ['/backup22.zip', 'zip', 'backup22'],
            'date suffix' => ['/backup-2024-01-01.tar.gz', 'tar.gz', 'backup-2024-01-01'],
            'old suffix' => ['/site_old.tgz', 'tgz', 'site_old'],
            'directory ignored' => ['/old/www.zip', 'zip', 'www'],
            'stacked suffixes' => ['/db_backup_final.7z', '7z', 'db_backup_final'],
            'tar.bz2' => ['/public_html.tar.bz2', 'tar.bz2', 'public_html'],
            'bare gz of archive name' => ['/backup.gz', 'gz', 'backup'],
            'plain tar' => ['/htdocs.tar', 'tar', 'htdocs'],
            'persona domain' => ['/example.com.zip', 'zip', 'example.com'],
            'www + persona domain' => ['/www.example.com.tar.gz', 'tar.gz', 'www.example.com'],
            'persona label' => ['/example-2023.zip', 'zip', 'example-2023'],
        ];
    }

    /**
     * @dataProvider backupNames
     */
    public function test_backup_style_names_match(string $path, string $ext, string $stem): void
    {
        self::assertSame([$ext, $stem], DecoyArchiveName::match($path, false, 'example.com'));
    }

    /**
     * @return array<string,array{0:string}>
     */
    public static function nonBackupNames(): array
    {
        return [
            'ordinary asset' => ['/assets/logo-pack.zip'],
            'unservable rar' => ['/backup.rar'],
            'unservable xz' => ['/backup.tar.xz'],
            'stem must be whole' => ['/backupfoo.zip'],
            'archive is not the extension' => ['/backup.zip.txt'],
            'sql dump gz' => ['/backup.sql.gz'],
            'csv bz2' => ['/data.csv.bz2'],
            'directory only' => ['/backup/'],
            'bare extension' => ['/.zip'],
            'other domain' => ['/othersite.com.zip'],
            'upper case (case-sensitive like Linux)' => ['/WWW.ZIP'],
            'mixed case' => ['/Backup.zip'],
        ];
    }

    /**
     * @dataProvider nonBackupNames
     */
    public function test_other_names_do_not_match(string $path): void
    {
        self::assertNull(DecoyArchiveName::match($path, false, 'example.com'));
    }

    public function test_request_host_names_match(): void
    {
        self::assertSame(['zip', 'shop.example.org'], DecoyArchiveName::match('/shop.example.org.zip', false, 'example.com', 'shop.example.org'));
        self::assertSame(['zip', 'shop'], DecoyArchiveName::match('/shop.zip', false, '', 'www.shop.example.org'));
        self::assertNull(DecoyArchiveName::match('/shop.zip', false, 'example.com', ''));
    }

    public function test_any_name_widens_to_every_servable_basename(): void
    {
        self::assertSame(['zip', 'logo-pack'], DecoyArchiveName::match('/assets/logo-pack.zip', true));
        self::assertSame(['7z', 'whatever_123'], DecoyArchiveName::match('/x/whatever 123.7z', true));
        self::assertNull(DecoyArchiveName::match('/x/Whatever.7z', true));
        self::assertNull(DecoyArchiveName::match('/backup.rar', true));
        self::assertNull(DecoyArchiveName::match('/dump.sql.gz', true));
    }

    public function test_stem_is_sanitized_and_capped(): void
    {
        $m = DecoyArchiveName::match('/' . str_repeat('a', 180) . '"x.zip', true);
        self::assertNotNull($m);
        self::assertSame(1, preg_match('/^[a-z0-9._-]{1,100}$/', $m[1]));
        self::assertSame(['zip', 'evil_name'], DecoyArchiveName::match('/..evil;name.zip', true));
    }

    public function test_long_digit_runs_fail_fast_without_a_pcre_error(): void
    {
        $start = microtime(true);
        for ($i = 0; $i < 50; $i++) {
            self::assertNull(DecoyArchiveName::match('/backup' . str_repeat('9', 240) . 'x.zip'));
        }
        self::assertSame(PREG_NO_ERROR, preg_last_error());
        self::assertLessThan(0.25, microtime(true) - $start, '50 crafted names must not backtrack');
        self::assertSame(['zip', substr('backup' . str_repeat('9', 240), 0, 100)], DecoyArchiveName::match('/backup' . str_repeat('9', 240) . '.zip'));
        self::assertSame(['zip', 'backup2024-01-01_old'], DecoyArchiveName::match('/backup2024-01-01_old.zip'));
        self::assertSame(['zip', 'backup20240101'], DecoyArchiveName::match('/backup20240101.zip'));
    }
}
