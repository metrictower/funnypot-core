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
 * FP-0557: the 10-git-config enrich must dress ONLY the real /.git/config surface (needle `git-config`),
 * not every bundle whose pid/id merely contains the substring "git" (github-gemfile-files, gitlab-*). A
 * .git/config body on /Gemfile or /.gitlab-ci.yml is an incoherent fingerprint tell.
 */
final class GitConfigNeedleScopeTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical', 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function body(string $path): string
    {
        $r = $this->engine()->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));

        return $r !== null ? (string) $r->body : '';
    }

    public function test_real_git_config_still_serves_the_config_body(): void
    {
        // The /.git/config bundle's needle IS `git-config`, so it still binds after dropping the bare `git`.
        self::assertStringContainsString('logallrefupdates', $this->body('/.git/config'), 'exposed .git/config decoy must still serve');
        self::assertStringContainsString('[remote "origin"]', $this->body('/.git/config'));
    }

    public function test_github_and_gitlab_surfaces_do_not_get_git_config(): void
    {
        // These were over-matched by the retired bare `git` substring needle (pid github / gitlab contain "git").
        foreach (['/Gemfile', '/Gemfile.lock', '/.gitlab-ci.yml'] as $path) {
            self::assertStringNotContainsString('logallrefupdates', $this->body($path),
                "{$path} must NOT serve a .git/config body (FP-0557 needle over-match)");
        }
    }
}
