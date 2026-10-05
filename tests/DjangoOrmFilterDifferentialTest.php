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
 * FP-0387: Django ORM lookup / sensitive-field injection DIFFERENTIAL decoy. /api/v1/users is an
 * exact-store 398 collection key; this owns_path rule intercepts it ONLY when an ORM lookup suffix is
 * present and returns a value-class differential — a plausible probe value gets a populated user list
 * (TRUE ~950B), an unlikely sentinel (empty / uuid-hex / tilde run) gets an empty envelope (FALSE ~53B),
 * so a scanner's SequenceMatcher.quick_ratio < 0.9 fires. Both 200, never 500. A benign GET (no suffix)
 * declines to the static 398 collection unchanged. Leaked creds are fabricated; nothing is reflected.
 * Fixture: full compiled corpus + attack artifact via Honeypot::respond() with attackEmulation on.
 */
final class DjangoOrmFilterDifferentialTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    /** @var array<string,Honeypot> per-seed engine cache — caps Honeypot churn across the seed sweeps. */
    private static $engines = [];

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (isset(self::$engines[$seed])) {
            return self::$engines[$seed];
        }
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;

        return self::$engines[$seed] = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function resp(string $path, string $query = '', string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', $path, $query, [], null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    /** SequenceMatcher.quick_ratio equivalent: 2*Σ min(count_a,count_b) / (len_a+len_b). */
    private function quickRatio(string $a, string $b): float
    {
        $ca = count_chars($a, 1);
        $cb = count_chars($b, 1);
        $m = 0;
        foreach ($ca as $k => $v) {
            if (isset($cb[$k])) {
                $m += min($v, $cb[$k]);
            }
        }
        $t = strlen($a) + strlen($b);

        return $t > 0 ? 2 * $m / $t : 1.0;
    }

    public function test_likely_probe_returns_user_records(): void
    {
        $b = $this->body($this->resp('/api/v1/users', 'password__startswith=pbkdf2'));
        self::assertStringContainsString('"data": [', $b);
        self::assertStringContainsString('"is_superuser": true', $b);
        self::assertStringContainsString('pbkdf2_sha256$', $b);
    }

    public function test_unlikely_probe_returns_empty(): void
    {
        foreach (['password__startswith=' . str_repeat('a1b2', 8), 'name__contains=' . str_repeat('~', 20), 'email__exact='] as $q) {
            $r = $this->resp('/api/v1/users', $q);
            self::assertSame(200, $r->status ?? null, "{$q} must be 200");
            self::assertStringContainsString('"total": 0', $this->body($r), "{$q} must be empty");
            self::assertStringContainsString('"data": []', $this->body($r), "{$q} empty data");
        }
    }

    public function test_differential_ratio_below_threshold(): void
    {
        $likely = $this->body($this->resp('/api/v1/users', 'password__startswith=pbkdf2'));
        $unlikely = $this->body($this->resp('/api/v1/users', 'password__startswith=' . str_repeat('a1b2', 8)));
        self::assertLessThan(0.85, $this->quickRatio($likely, $unlikely), 'quick_ratio must be < 0.85 (Artemis fires below 0.9)');
        self::assertLessThan(0.8 * strlen($likely), strlen($unlikely), 'FALSE body must be materially shorter');
    }

    public function test_never_500_full_sweep(): void
    {
        $suffixes = ['__exact', '__iexact', '__contains', '__icontains', '__startswith', '__istartswith',
            '__endswith', '__iendswith', '__gt', '__gte', '__lt', '__lte', '__regex', '__iregex'];
        $values = ['pbkdf2', 'bcrypt', '$', '@', '1', '0', '^a', '.*', '', 'f', str_repeat('~', 20), str_repeat('f', 32)];
        foreach ($suffixes as $s) {
            foreach ($values as $v) {
                $r = $this->resp('/api/v1/users', 'field' . $s . '=' . $v);
                self::assertNotNull($r, "field{$s}={$v} must serve");
                self::assertLessThan(500, $r->status, "field{$s}={$v} must never 5xx");
            }
        }
    }

    public function test_sensitive_field_probes(): void
    {
        self::assertStringContainsString('"is_superuser": true', $this->body($this->resp('/api/v1/users', 'is_superuser__exact=1')));
        self::assertStringContainsString('"is_staff": true', $this->body($this->resp('/api/v1/users', 'is_staff__exact=1')));
        self::assertStringContainsString('"total": 3', $this->body($this->resp('/api/v1/users', 'password__contains=$')));
        self::assertStringContainsString('"total": 3', $this->body($this->resp('/api/v1/users', 'email__contains=@')));
    }

    public function test_benign_collection_unchanged(): void
    {
        $r = $this->resp('/api/v1/users');
        self::assertSame(200, $r->status ?? null);
        self::assertStringContainsString('per_page', $this->body($r), 'benign GET must serve the 398 collection');
        self::assertStringNotContainsString('is_superuser', $this->body($r), 'benign GET must not leak the ORM-probe rows');
        self::assertStringNotContainsString('pbkdf2_sha256', $this->body($r));
    }

    public function test_no_collision_with_method_override(): void
    {
        // FP-0454 owns the /{id} detail path; this rule owns only the collection.
        $del = $this->engine()->respond(new RequestContext('DELETE', '/api/v1/users/5', '', [], null, 'x.test'));
        self::assertSame(401, $del->status ?? null, 'the /{id} detail path must still be FP-0454 (401)');
    }

    public function test_no_reflection(): void
    {
        // A canary in a (likely-shaped) probe value must never appear in the served body.
        $b = $this->body($this->resp('/api/v1/users', 'username__startswith=ZZCANARYZZ'));
        self::assertStringNotContainsString('ZZCANARYZZ', $b, 'the probe value must not be reflected');
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        for ($s = 0; $s < 400; $s++) {
            $true = $this->body($this->resp('/api/v1/users', 'password__startswith=pbkdf2', (string) $s));
            $false = $this->body($this->resp('/api/v1/users', 'q__contains=' . str_repeat('a1b2', 8), (string) $s));
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $true), "seed {$s} TRUE denylist run");
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $false), "seed {$s} FALSE denylist run");
        }
    }

    public function test_deterministic_same_seed(): void
    {
        self::assertSame(
            $this->body($this->resp('/api/v1/users', 'password__startswith=pbkdf2', 'seedZ')),
            $this->body($this->resp('/api/v1/users', 'password__startswith=pbkdf2', 'seedZ')),
            'same seed must yield an identical TRUE body'
        );
    }
}
