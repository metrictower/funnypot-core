<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0443: fuxploider upload-confirmation. fuxploider (and its nastygif/jpg/htaccess templates) upload a
 * phpinfo payload, fetch the returned /wp-content/uploads/<name>.php, and confirm code execution on a
 * FIXED regex (templates.json): `<title>phpinfo()</title> (.|\n)* <h2>PHP License</h2>`. The honeypot
 * serves a phpinfo page on that uploaded-file fetch so fuxploider "confirms", while still carrying the
 * uid=33 id-output line the generic webshell-grep confirmation relies on. The regular /phpinfo decoy
 * also now carries the PHP License section. INERT: the page is static; no uploaded byte is reflected.
 */
final class FuxploiderUploadConfirmTest extends TestCase
{
    /** fuxploider's exact PHP/GIF/JPG/htaccess codeExecRegex (templates.json). */
    private const FUXPLOIDER_REGEX = '~\<title\>phpinfo\(\)\</title\>(.|\n)*\<h2\>PHP License\</h2\>~';

    private function engine(): Honeypot
    {
        return new Honeypot(
            new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php'),
            new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
                static fn (RequestContext $r): string => 'fixed', 'coherent', Style::REALISTIC, 'critical',
                65536, 0, 0, true, null, null, null, 'fixed')
        );
    }

    private function get(string $path): ?object
    {
        return $this->engine()->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
    }

    /** @return array<string,array{0:string}> uploaded-file fetch paths fuxploider would request */
    public function uploadPaths(): array
    {
        return [
            'flat'   => ['/wp-content/uploads/a1b2c3d4.php'],
            'dated'  => ['/wp-content/uploads/2023/07/wp-conf.php'],
            'nasty'  => ['/wp-content/uploads/template.php'],
        ];
    }

    /** @dataProvider uploadPaths */
    public function test_uploaded_file_fetch_confirms_fuxploider(string $path): void
    {
        $r = $this->get($path);
        self::assertNotNull($r, "{$path} must serve a confirmation page");
        self::assertSame(200, $r->status);
        self::assertSame(1, preg_match(self::FUXPLOIDER_REGEX, $r->body), "fuxploider codeExecRegex must match: {$path}");
        // Coherent phpinfo page — deliberately NO `uid=…` id-output line (a real phpinfo never prints
        // one; that would be a tell). The webshell-grep uid=33 confirmation stays on the direct-shell paths.
        self::assertStringNotContainsString('uid=33(www-data)', $r->body, "phpinfo page carries no id-output tell: {$path}");
    }

    public function test_phpinfo_decoy_also_satisfies_fuxploider(): void
    {
        $r = $this->get('/phpinfo.php');
        self::assertNotNull($r);
        self::assertSame(1, preg_match(self::FUXPLOIDER_REGEX, $r->body), 'the /phpinfo decoy carries the PHP License section');
    }

    public function test_known_shell_name_still_serves_its_own_panel_not_phpinfo(): void
    {
        // Precedence: a known-shell name under uploads keeps its family panel (c99), NOT the phpinfo
        // confirmation — the uploads-phpinfo branch sorts AFTER the family-name branches.
        $r = $this->get('/wp-content/uploads/c99.php');
        self::assertNotNull($r);
        self::assertStringContainsString('c99shell', $r->body, 'c99 name keeps its self-identifying panel');
        self::assertSame(0, preg_match(self::FUXPLOIDER_REGEX, $r->body), 'c99 panel is not a phpinfo page');
    }

    public function test_uploaded_file_body_never_reflects_the_requested_name(): void
    {
        // Inert: the uploaded filename in the path must not be echoed into the served body.
        $r = $this->get('/wp-content/uploads/CANARYxk93qz7w.php');
        self::assertNotNull($r);
        self::assertStringNotContainsString('CANARYxk93qz7w', $r->body, 'no reflection of the uploaded name');
    }
}
