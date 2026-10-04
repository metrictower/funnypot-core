<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * FP-0419: the modern AI / CI-CD key canary catalog. Each new {{persona.cloud.*}} shape must match its
 * vendor's exact format (so a secret scanner — Caido ai-key/cicd-token, trufflehog, gitleaks — bites),
 * be seed-derived (per-deploy unique, no cross-deploy correlation) and non-working, and never form the
 * fingerprint denylist's bare 6-digit run. Shapes are asserted by REGEX; no contiguous secret literal is
 * written here (GitHub push-protection / AGENT-EXECUTION-RULES §3).
 */
final class CanaryTokenCatalogTest extends TestCase
{
    /** @return array<string,string> field => anchored shape regex */
    private static function shapes(): array
    {
        // Prefixes are split so no line is a scannable secret literal.
        // \b-anchored (NAME=value\n context) so these match the real Caido/gitleaks/trufflehog rules,
        // not just a loose shape. A trailing '-' on glpat- would fail the closing \b (the FP-0419 review
        // fix); the openai key must carry the T3BlbkFJ infix (asserted separately).
        return [
            'cloud.openai.projectKey'     => '~\b' . 'sk-' . 'proj-[A-Za-z0-9_-]{40,}\b~',
            'cloud.huggingface.token'     => '~\b' . 'hf' . '_[A-Za-z]{34}\b~',
            'cloud.groq.apiKey'           => '~\b' . 'gsk' . '_[A-Za-z0-9]{52}\b~',
            'cloud.buildkite.token'       => '~\b' . 'bkua' . '_[a-f0-9]{40}\b~',
            'cloud.circleci.token'        => '~\b[a-f0-9]{40}\b~',
            'cloud.github.pat'            => '~\b' . 'ghp' . '_[A-Za-z0-9]{36}\b~',
            'cloud.github.fineGrainedPat' => '~\b' . 'github_pat' . '_[A-Za-z0-9]{82}\b~',
            'cloud.gitlab.pat'            => '~\b' . 'glpat' . '-[A-Za-z0-9_-]{20,}\b~',
            'cloud.slack.botToken'        => '~\b' . 'xoxb' . '-[0-9A-Za-z-]{40}\b~',
        ];
    }

    public function test_every_new_shape_matches_its_vendor_regex(): void
    {
        $p = PersonaIdentity::fromSeed(crc32('demo-host'));
        foreach (self::shapes() as $field => $rx) {
            $v = (string) $p->field($field);
            self::assertSame(1, preg_match($rx, $v), "{$field} must match its vendor shape, got: {$v}");
        }
    }

    public function test_shapes_and_fingerprint_safety_hold_across_seeds(): void
    {
        $shapes = self::shapes();
        for ($s = 0; $s < 3000; $s++) {
            $p = PersonaIdentity::fromSeed($s);
            foreach ($shapes as $field => $rx) {
                $v = (string) $p->field($field);
                self::assertSame(1, preg_match($rx, $v), "seed {$s} {$field} shape");
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $v), "seed {$s} {$field} formed a denylisted run: {$v}");
            }
        }
    }

    public function test_keys_are_per_deploy_unique_not_fleet_constant(): void
    {
        // Anti-correlation: two deploys must never share a key (per-seed derivation).
        foreach (array_keys(self::shapes()) as $field) {
            $a = (string) PersonaIdentity::fromSeed(crc32('box-A'))->field($field);
            $b = (string) PersonaIdentity::fromSeed(crc32('box-B'))->field($field);
            self::assertNotSame($a, $b, "{$field} must differ across deploys");
            // Deterministic within a deploy.
            self::assertSame($a, (string) PersonaIdentity::fromSeed(crc32('box-A'))->field($field));
        }
    }

    public function test_openai_key_carries_the_vendor_infix_and_gitlab_has_no_trailing_dash(): void
    {
        for ($s = 0; $s < 2000; $s++) {
            $p = PersonaIdentity::fromSeed($s);
            self::assertStringContainsString('T3Blb' . 'kFJ', (string) $p->field('cloud.openai.projectKey'),
                "seed {$s}: openai project key must carry the vendor infix (gitleaks/trufflehog require it)");
            self::assertNotSame('-', substr((string) $p->field('cloud.gitlab.pat'), -1),
                "seed {$s}: gitlab PAT must not end in '-' (breaks a \\b-anchored scanner rule)");
        }
    }

    public function test_env_production_decoy_leaks_the_new_catalog(): void
    {
        $idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'high', 65536, 0, 0, false);
        $h = new Honeypot(new PhpArrayStore($idx), $cfg);
        foreach (['/.env.production', '/.env'] as $path) {
            $body = (string) ($h->respond(new RequestContext('GET', $path, '', [], null, 'x.test'))->body ?? '');
            foreach (['OPENAI_API_KEY=sk-' . 'proj-', 'GITHUB_TOKEN=ghp' . '_'] as $marker) {
                self::assertStringContainsString($marker, $body, "the {$path} decoy must leak {$marker}");
            }
        }
    }
}
