<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Crs;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * The CRS LFI catch-all is detected on the whole request but served only when the query or body carries
 * the match: a "failed to open stream" read error answers a parameter that names a file, never a bare
 * request for a restricted path.
 */
final class CrsLfiServeOnPayloadTest extends TestCase
{
    private const WARNING = 'failed to open stream';

    private static function engine(bool $payloadInspection = false): Honeypot
    {
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool {
                return true;
            },
            'matched-only',
            null,
            'coherent',
            Style::REALISTIC,
            'critical',
            65536,
            0,
            0,
            true
        );
        $config->payloadInspection = $payloadInspection;

        return Honeypot::default($config);
    }

    private static function request(string $path, string $query = ''): RequestContext
    {
        return new RequestContext('GET', $path, $query, ['user-agent' => 'Mozilla/5.0', 'host' => 'lab.example'], null, 'lab.example', 'http');
    }

    /** @return array<string,array{0:string}> */
    public function barePathProvider(): array
    {
        return [
            'wp-config.php' => ['/wp-config.php'],
            '.env~' => ['/.env~'],
            '.git/objects' => ['/.git/objects'],
            '.git/index' => ['/.git/index'],
            'config.ini' => ['/config.ini'],
            'unmapped path traversal' => ['/%2e%2e/%2e%2e/%2e%2e/var/log/nginx/error.log'],
        ];
    }

    /** @dataProvider barePathProvider */
    public function test_a_bare_path_is_detected_but_not_served_the_read_error(string $path): void
    {
        $engine = self::engine();
        $verdict = $engine->classify(self::request($path), SiteProfile::empty());

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification, $path);
        self::assertContains('attack-crs-lfi', $verdict->detection->templateIds(), $path);
        self::assertNull($verdict->fakeHandle, $path);

        self::assertNull($engine->respond(self::request($path)), $path);
    }

    /** @return array<string,array{0:string,1:string}> */
    public function payloadProvider(): array
    {
        return [
            'file parameter' => ['/viewfile.php', 'file=../../../../var/www/nothing'],
            'page parameter' => ['/zz-unrouted', 'page=../../../../var/www/nothing'],
        ];
    }

    /** @dataProvider payloadProvider */
    public function test_a_payload_that_names_a_file_still_gets_the_read_error(string $path, string $query): void
    {
        $r = self::engine()->respond(self::request($path, $query));

        self::assertNotNull($r, "{$path}?{$query}");
        self::assertStringContainsString(self::WARNING, $r->body);
    }

    public function test_an_archive_name_with_a_restricted_token_still_gets_the_archive_decoy(): void
    {
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool {
                return true;
            },
            'matched-only',
            null,
            'coherent',
            Style::REALISTIC,
            'critical',
            2000000,
            0,
            0,
            true
        );
        $config->decoyArchives = true;
        $config->decoyArchiveAnyName = true;
        $engine = Honeypot::default($config);

        $verdict = $engine->classify(self::request('/wp-config.php.zip'), SiteProfile::empty());
        self::assertContains('attack-crs-lfi', $verdict->detection->templateIds(), 'the restricted token is still detected');

        $r = $engine->respond(self::request('/wp-config.php.zip'));
        self::assertNotNull($r, 'a detected-but-not-served match must not hide the archive decoy');
        self::assertSame('application/zip', $r->headers['Content-Type'] ?? null);
    }

    public function test_payload_inspection_on_a_real_route_still_classifies_the_catch_all(): void
    {
        $profile = new SiteProfile([], static function (): bool {
            return true;
        });
        $verdict = self::engine(true)->classify(self::request('/blog', 'file=../../../../var/log/nginx/error.log'), $profile);

        self::assertContains('attack-crs-lfi', $verdict->detection->templateIds());
    }
}
