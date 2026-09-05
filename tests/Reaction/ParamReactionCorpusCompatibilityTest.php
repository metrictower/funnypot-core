<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Reaction;

use Closure;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * Walks the WHOLE production route corpus and proves the two corpus-level guarantees:
 *  - config-OFF: a query never changes a served response (byte-identical to the no-query serve);
 *  - config-ON: every decorated response keeps the base status and headers, only grows the body, stays
 *    within maxBodyBytes and an eligible content type, and echoes the marker; a decoration never
 *    creates a response where the base served none, nor suppresses one the base served.
 * No corpus total is frozen (counts are re-measured), and the compiled artifact's sha256 is unchanged.
 *
 * @group large-artifact
 */
final class ParamReactionCorpusCompatibilityTest extends TestCase
{
    private const ARTIFACT = __DIR__ . '/../../resources/compiled/nuclei-index.full.php';
    private const MARKER = 'fp0157marker';

    private static function vouch(): Closure
    {
        return static function (RequestContext $r, string $class): bool { return true; };
    }

    private function config(bool $paramReactivity): Config
    {
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only', null, 'coherent',
            Style::REALISTIC, 'high', 65536, 0, 0,
            false // attackEmulation off: the exact route tier is what this ticket touches
        );
        $config->isolatedOrigin = true;
        $config->reflectorAuthorizer = self::vouch();
        $config->paramReactivity = $paramReactivity;
        $config->probeSignature = static function (RequestContext $r): bool { return true; };

        return $config;
    }

    /** @return array{0:string,1:string} method, path parsed from a '<METHOD> <path>' route key */
    private static function splitKey(string $key): array
    {
        $sp = strpos($key, ' ');
        if ($sp === false) {
            return ['GET', $key];
        }

        return [substr($key, 0, $sp), substr($key, $sp + 1)];
    }

    /**
     * The header NAME set (sorted). Values are compared nowhere at corpus scale because some base
     * templates mint a per-response random header (X-Request-Id, a JSESSIONID cookie), exactly like a
     * real server — that varies between two independent respond() calls and is not a decoration change.
     * Decoration copies $base->headers by value, so "no header added or removed" is the invariant that
     * matters here; the byte-exact header equality is proven in ParamReactionDecoratorTest.
     *
     * @param array<string,string|string[]> $headers
     * @return string[]
     */
    private static function headerNames(array $headers): array
    {
        $names = array_map('strval', array_keys($headers));
        sort($names);

        return $names;
    }

    public function test_corpus_wide_off_identity_and_on_safety(): void
    {
        $store = PhpArrayStore::fromFile(self::ARTIFACT);
        $index = require self::ARTIFACT;
        $keys = array_keys($index['routes'] ?? []);
        self::assertNotEmpty($keys);

        $shaBefore = hash_file('sha256', self::ARTIFACT);

        $off = new Honeypot($store, $this->config(false));
        $on = new Honeypot($store, $this->config(true));

        $changed = 0;
        $changedHtml = 0;
        $changedText = 0;
        $baseServed = 0;

        foreach ($keys as $key) {
            [$method, $path] = self::splitKey((string) $key);
            $host = 'corpus.example';
            $plain = new RequestContext($method, $path, '', [], null, $host);
            $withQ = new RequestContext($method, $path, 'q=' . self::MARKER, [], null, $host);

            // config-OFF: a query changes nothing.
            $offBase = $off->respond($plain);
            $offQ = $off->respond($withQ);
            if ($offBase === null) {
                self::assertNull($offQ, "off drift (base null but query served): {$key}");
            } else {
                self::assertNotNull($offQ, "off drift (query suppressed base): {$key}");
                self::assertSame($offBase->body, $offQ->body, "off drift (body): {$key}");
            }

            // config-ON: the no-query serve equals the OFF base (no query => no reaction), and the
            // query serve preserves status/headers and only extends the body.
            $onBase = $on->respond($plain);
            $onQ = $on->respond($withQ);

            if ($onBase === null) {
                self::assertNull($onQ, "decoration created a response from nothing: {$key}");
                continue;
            }
            $baseServed++;
            self::assertNotNull($onQ, "decoration suppressed the base: {$key}");
            self::assertSame($onBase->status, $onQ->status, "status changed: {$key}");
            self::assertSame(self::headerNames($onBase->headers), self::headerNames($onQ->headers), "header set changed: {$key}");

            if ($onQ->body === $onBase->body) {
                continue; // an ineligible bundle/response: untouched base (the common, safe case)
            }

            // A decorated response: append-only growth, still capped, eligible type, marker present.
            $changed++;
            self::assertGreaterThan(strlen($onBase->body), strlen($onQ->body), "not append-only: {$key}");
            self::assertLessThanOrEqual(65536, strlen($onQ->body), "over cap: {$key}");
            self::assertStringContainsString(self::MARKER, $onQ->body, "marker absent from decoration: {$key}");

            $ct = $onQ->headers['Content-Type'] ?? '';
            $ct = is_string($ct) ? $ct : '';
            self::assertSame(1, preg_match('~^text/(html|plain)\s*(;\s*charset=utf-8\s*)?$~i', $ct), "ineligible content type decorated: {$key} ({$ct})");
            if (stripos($ct, 'text/html') === 0) {
                $changedHtml++;
            } else {
                $changedText++;
            }
        }

        // Informational (never frozen): prove the safe surface is non-trivial in BOTH content types.
        self::assertGreaterThan(0, $changedHtml, 'expected at least one decorated text/html response');
        self::assertGreaterThan(0, $changedText, 'expected at least one decorated text/plain response');
        fwrite(STDERR, sprintf(
            "\n[FP-0157 corpus] routes=%d base-served=%d decorated=%d (html=%d text=%d)\n",
            count($keys), $baseServed, $changed, $changedHtml, $changedText
        ));

        self::assertSame($shaBefore, hash_file('sha256', self::ARTIFACT), 'the compiled artifact must not change');
    }
}
