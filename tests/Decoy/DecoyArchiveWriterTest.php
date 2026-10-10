<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Decoy;

use Funnypot\Core\Decoy\DecoyArchiveWriter;
use PHPUnit\Framework\TestCase;

final class DecoyArchiveWriterTest extends TestCase
{
    /**
     * @return list<array{0:string,1:string,2:int}>
     */
    private function members(): array
    {
        return [
            ['site/site.7z', random_bytes(3000), 1700000000],
            ['site/README.txt', "hello\n", 1700000100],
            ['site/empty.txt', '', 1700000200],
        ];
    }

    public function test_zip_store_round_trips_through_a_minimal_parser(): void
    {
        $members = $this->members();
        $zip = DecoyArchiveWriter::zipStore($members);

        $eocd = strrpos($zip, "PK\x05\x06");
        self::assertNotFalse($eocd);
        $e = unpack('Vsig/vdisk/vcd_disk/vcount/vtotal/Vcd_size/Vcd_off/vcomment', substr($zip, $eocd, 22));
        self::assertSame(3, $e['total']);

        $off = $e['cd_off'];
        foreach ($members as [$name, $data]) {
            $c = unpack('Vsig/vmade/vneed/vflags/vmethod/vtime/vdate/Vcrc/Vcsize/Vusize/vnlen/velen/vclen/vdisk/viattr/Vexattr/Vloff', substr($zip, $off, 46));
            self::assertSame(0x02014b50, $c['sig']);
            self::assertSame($name, substr($zip, $off + 46, $c['nlen']));
            self::assertSame(0, $c['method']);
            $l = unpack('Vsig/vneed/vflags/vmethod/vtime/vdate/Vcrc/Vcsize/Vusize/vnlen/velen', substr($zip, $c['loff'], 30));
            self::assertSame(0x04034b50, $l['sig']);
            $got = substr($zip, $c['loff'] + 30 + $l['nlen'] + $l['elen'], $l['csize']);
            self::assertSame($data, $got);
            self::assertSame(crc32($data) & 0xffffffff, $c['crc'] & 0xffffffff);
            $off += 46 + $c['nlen'];
        }
    }

    public function test_zip_store_opens_with_ziparchive_when_available(): void
    {
        if (!class_exists(\ZipArchive::class)) {
            self::markTestSkipped('ext-zip not loaded');
        }
        $path = tempnam(sys_get_temp_dir(), 'fpzip');
        file_put_contents($path, DecoyArchiveWriter::zipStore($this->members()));
        $z = new \ZipArchive();
        self::assertTrue($z->open($path, \ZipArchive::CHECKCONS));
        self::assertSame("hello\n", $z->getFromName('site/README.txt'));
        self::assertSame(3, $z->numFiles);
        $z->close();
        unlink($path);
    }

    public function test_ustar_headers_checksums_and_alignment(): void
    {
        $members = $this->members();
        $tar = DecoyArchiveWriter::ustar($members);
        self::assertSame(0, strlen($tar) % 10240);

        $off = 0;
        foreach ($members as [$name, $data, $mtime]) {
            $h = substr($tar, $off, 512);
            self::assertSame("ustar\0" . '00', substr($h, 257, 8));
            self::assertSame($name, rtrim(substr($h, 0, 100), "\0"));
            $sum = 0;
            for ($i = 0; $i < 512; $i++) {
                $sum += ($i >= 148 && $i < 156) ? 32 : ord($h[$i]);
            }
            self::assertSame($sum, octdec(trim(substr($h, 148, 7), "\0 ")));
            $size = octdec(trim(substr($h, 124, 11)));
            self::assertSame(strlen($data), $size);
            self::assertSame($mtime, octdec(trim(substr($h, 136, 11))));
            self::assertSame($data, substr($tar, $off + 512, $size));
            $off += 512 + (int) (ceil($size / 512) * 512);
        }
        self::assertSame(str_repeat("\0", 1024), substr($tar, $off, 1024));
    }

    public function test_writers_are_deterministic(): void
    {
        $m = [['a/b.7z', 'payload', 1700000000]];
        self::assertSame(DecoyArchiveWriter::zipStore($m), DecoyArchiveWriter::zipStore($m));
        self::assertSame(DecoyArchiveWriter::ustar($m), DecoyArchiveWriter::ustar($m));
    }
}
