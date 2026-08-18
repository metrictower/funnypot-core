<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * Brand-new product pages (route templates with a new_page block, folded into the compiled
 * index by `funnypot merge-routes`) must route and serve like any other bundle: detect()
 * signals, respond() serves the authored body, and — the whole point — the response
 * validates against the synthesized bundle (respond() only returns non-null when it does).
 */
final class NewPageRoutingTest extends TestCase
{
    private function inverter(): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,
            responseStyle: 'realistic',
            personaSeed: static fn (RequestContext $r): string => 'fixed'
        ));
    }

    /**
     * @dataProvider pages
     */
    public function test_new_page_routes_and_serves(string $path, int $status, string $marker): void
    {
        $inv = $this->inverter();

        self::assertTrue($inv->detect(new RequestContext('GET', $path))->matched, "{$path} must be detected");

        $resp = $inv->respond(new RequestContext('GET', $path));
        self::assertNotNull($resp, "{$path} must serve a fake");
        self::assertSame($status, $resp->status, "{$path} status");
        self::assertStringContainsString($marker, $resp->body, "{$path} must carry its marker");
    }

    /**
     * @return array<string, array{0:string,1:int,2:string}>
     */
    public static function pages(): array
    {
        return [
            'credentials.txt'  => ['/credentials.txt', 200, 'AWS_SECRET_ACCESS_KEY'],
            'terraform.tfstate' => ['/terraform.tfstate', 200, '"terraform_version"'],
            'users.csv'        => ['/users.csv', 200, 'password_hash'],
            'sql backup'       => ['/backup.sql', 200, 'CREATE TABLE'],
            'basic-auth 401'   => ['/private/', 401, 'Authorization Required'],
            'phpmyadmin login' => ['/phpmyadmin/', 200, 'phpMyAdmin'],
        ];
    }

    public function test_basic_auth_emits_www_authenticate(): void
    {
        $resp = $this->inverter()->respond(new RequestContext('GET', '/private/'));

        self::assertNotNull($resp);
        self::assertArrayHasKey('Www-Authenticate', $resp->headers);
        self::assertStringContainsString('Basic realm=', $resp->headers['Www-Authenticate']);
    }

    public function test_tomcat_manager_enriches_existing_bundle(): void
    {
        $resp = $this->inverter()->respond(new RequestContext('GET', '/manager/html'));

        self::assertNotNull($resp);
        self::assertStringContainsString('Tomcat Web Application Manager', $resp->body);
    }
}
