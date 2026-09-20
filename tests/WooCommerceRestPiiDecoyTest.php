<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * FP-0413 — WooCommerce store persona + unauthenticated REST / CVE PII decoys.
 *
 * Drives the REAL engine over the FULL compiled index (nuclei-index.full.php) + compiled attack file
 * (the NextjsRscPersonaTest pattern), so classify()'s owns_path override + the persona gate run on the
 * true serve path. The store is a `GET /` persona (route-woo-store); every other woo surface is an
 * attack-tier rule gated on that pid, so the tests are seed-sensitive: they pin a store seed and a
 * non-store seed and assert the surfaces fire only on the store.
 */
final class WooCommerceRestPiiDecoyTest extends TestCase
{
    private const INDEX = __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    private const ATTACK = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    /** @var array<string,mixed>|null */
    private static $index;

    /** @return array<string,mixed> */
    private function index(): array
    {
        if (self::$index === null) {
            self::$index = require self::INDEX;
        }

        return self::$index;
    }

    /** A full engine pinned to one persona seed, attack tier live, root `/` allowed to serve. */
    private function engine(string $seed): Honeypot
    {
        return new Honeypot(new PhpArrayStore($this->index()), new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            'realistic',
            'critical',
            65536,
            0,
            0,
            true,
            null,
            null,
            static function (RequestContext $r): bool { return true; },
            '',
            [],
            true
        ));
    }

    /** The deploy's served `/` persona is route-woo-store ⟺ its shell carries the wc-blocks marker. */
    private function servedWooStore(Honeypot $e): bool
    {
        $r = $e->respond(new RequestContext('GET', '/'));

        return $r !== null && strpos($r->body, 'wc-blocks-style-css') !== false;
    }

    /** First seed (0..$max) whose served `/` persona is route-woo-store. */
    private function firstStoreSeed(int $max = 5000): string
    {
        for ($s = 0; $s <= $max; $s++) {
            if ($this->servedWooStore($this->engine((string) $s))) {
                return (string) $s;
            }
        }
        self::fail("no route-woo-store-selecting seed found in 0..{$max} — the store shell is not served");
    }

    /** First seed (0..$max) whose served `/` persona is NOT route-woo-store. */
    private function firstNonStoreSeed(int $max = 5000): string
    {
        for ($s = 0; $s <= $max; $s++) {
            if (!$this->servedWooStore($this->engine((string) $s))) {
                return (string) $s;
            }
        }
        self::fail("every seed served route-woo-store in 0..{$max} — cannot exercise the gate-closed branch");
    }

    // --- 1. store `/` homepage ---------------------------------------------------------------------

    public function test_store_home_serves_woocommerce_markers(): void
    {
        $resp = $this->engine($this->firstStoreSeed())->respond(new RequestContext('GET', '/'));

        self::assertNotNull($resp, 'the store shell must serve for a route-woo-store seed');
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('WooCommerce ', $resp->body, 'generator meta marker');
        self::assertStringContainsString('woocommerce', $resp->body, 'woocommerce body/asset markers');
        self::assertStringContainsString('wc-blocks-style-css', $resp->body, 'wc-blocks marker (the served-pid witness)');
    }

    // --- 2. public Store API products (NO PII) -----------------------------------------------------

    public function test_store_products_public_and_carry_no_pii(): void
    {
        $resp = $this->engine($this->firstStoreSeed())->respond(new RequestContext('GET', '/wp-json/wc/store/v1/products'));

        self::assertNotNull($resp, 'wc/store/v1/products must serve on a store deploy');
        self::assertSame(200, $resp->status);
        self::assertSame('application/json', $resp->headers['Content-Type'] ?? null);
        self::assertStringContainsString('"prices":', $resp->body, 'a product array with prices');
        self::assertStringContainsString('"permalink":', $resp->body);
        // Store API restraint: the public products surface exposes no customer/order PII.
        self::assertStringNotContainsStringIgnoringCase('"email"', $resp->body, 'no email on the public Store API');
        self::assertStringNotContainsStringIgnoringCase('"billing"', $resp->body, 'no billing on the public Store API');
        self::assertStringNotContainsStringIgnoringCase('"customer"', $resp->body, 'no customer on the public Store API');
    }

    // --- 3. wc/v3 management API unauth → the REAL 401 --------------------------------------------

    public function test_wc_v3_unauth_returns_cannot_view_401(): void
    {
        $e = $this->engine($this->firstStoreSeed());
        foreach (['customers', 'orders', 'coupons', 'system-status'] as $endpoint) {
            $resp = $e->respond(new RequestContext('GET', '/wp-json/wc/v3/' . $endpoint));
            self::assertNotNull($resp, "wc/v3/{$endpoint} must serve the 401 on a store deploy");
            self::assertSame(401, $resp->status, "wc/v3/{$endpoint} unauth status");
            self::assertSame('application/json', $resp->headers['Content-Type'] ?? null);
            self::assertStringContainsString('woocommerce_rest_cannot_view', $resp->body, "wc/v3/{$endpoint} witness code");
            self::assertStringContainsString('"status":401', $resp->body, "wc/v3/{$endpoint} status body");
            self::assertStringNotContainsStringIgnoringCase('"email"', $resp->body, 'no PII leaks from the 401 shape');
        }
        // The legacy alias behaves the same.
        $legacy = $e->respond(new RequestContext('GET', '/wc-api/v3/orders'));
        self::assertNotNull($legacy);
        self::assertSame(401, $legacy->status);
        self::assertStringContainsString('woocommerce_rest_cannot_view', $legacy->body);
    }

    // --- 4. wc-augmented /wp-json index -----------------------------------------------------------

    public function test_wp_json_index_advertises_wc_namespaces_on_store(): void
    {
        $resp = $this->engine($this->firstStoreSeed())->respond(new RequestContext('GET', '/wp-json'));

        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('"wc/store/v1"', $resp->body, 'Store API namespace advertised');
        self::assertStringContainsString('"wc/v3"', $resp->body, 'wc/v3 namespace advertised');
    }

    // --- 5. CVE-2023-28121 header impersonation → 201 admin ---------------------------------------

    public function test_cve_2023_28121_header_creates_admin(): void
    {
        $e = $this->engine($this->firstStoreSeed());

        // Header present + POST → 201 admin.
        $exploit = $e->respond(new RequestContext(
            'POST',
            '/wp-json/wp/v2/users',
            '',
            ['X-WCPAY-PLATFORM-CHECKOUT-USER' => '1'],
            '{"username":"attacker","email":"a@a.test","roles":["administrator"]}'
        ));
        self::assertNotNull($exploit, 'the auth-bypass POST must serve the 201');
        self::assertSame(201, $exploit->status, 'CVE-2023-28121 returns 201 Created');
        self::assertStringContainsString('"roles":["administrator"]', $exploit->body, 'a synthetic admin user');

        // Same POST WITHOUT the header → NOT the 201 (proves the header gate).
        $noHeader = $e->respond(new RequestContext('POST', '/wp-json/wp/v2/users', '', [], '{}'));
        if ($noHeader !== null) {
            self::assertNotSame(201, $noHeader->status, 'no header ⇒ no admin-create');
        }

        // GET /wp-json/wp/v2/users → the route-tier author enum still wins (no collision).
        $get = $e->respond(new RequestContext('GET', '/wp-json/wp/v2/users'));
        self::assertNotNull($get);
        self::assertSame(200, $get->status);
        self::assertStringContainsString('"avatar_urls"', $get->body, 'GET is the 345 author enum, not the 201');
        self::assertStringNotContainsString('"roles":["administrator"]', $get->body);
    }

    // --- 6. CVE-2023-34000 pay-for-order IDOR → honeytoken PII ------------------------------------

    public function test_cve_2023_34000_leaks_honeytoken_pii(): void
    {
        $resp = $this->engine($this->firstStoreSeed())->respond(new RequestContext(
            'GET',
            '/checkout/order-pay/45812',
            'pay_for_order=true&key=wc_order_abc123',
            [],
            ''
        ));

        self::assertNotNull($resp, 'the pay-for-order IDOR must serve on a store deploy');
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('text/html', $resp->headers['Content-Type'] ?? '');
        self::assertStringContainsString('wc_stripe_params', $resp->body, 'the localized JS var witness');
        self::assertStringContainsString('billing_email', $resp->body, 'leaked billing PII keys');

        // The order id in the path is never reflected into the body (no reflection).
        self::assertStringNotContainsString('45812', $resp->body, 'the order id must never be reflected');

        // The leaked email is a synthetic honeytoken, not a real inbox / not example.com.
        self::assertSame(1, preg_match('/"billing_email":"([^"]+)"/', $resp->body, $m), 'a billing_email value');
        $email = $m[1];
        self::assertStringContainsString('@', $email);
        $domain = substr($email, strpos($email, '@') + 1);
        self::assertNotSame('example.com', $domain, 'honeytoken, not the example.com placeholder');
        self::assertNotSame('gmail.com', $domain, 'honeytoken, not a real inbox');
        self::assertStringContainsString('.', $domain, 'a real-looking synthetic domain');
    }

    // --- 7. non-store deploy: gate closed ---------------------------------------------------------

    public function test_non_store_deploy_declines_all_woo_surfaces(): void
    {
        $e = $this->engine($this->firstNonStoreSeed());

        // The gated surfaces decline to the app's plain 404 (respond null) or at least never the woo body.
        $products = $e->respond(new RequestContext('GET', '/wp-json/wc/store/v1/products'));
        self::assertTrue($products === null || strpos($products->body, '"prices":') === false, 'no products off-store');

        $v3 = $e->respond(new RequestContext('GET', '/wp-json/wc/v3/customers'));
        self::assertTrue($v3 === null || strpos($v3->body, 'woocommerce_rest_cannot_view') === false, 'no wc/v3 401 off-store');

        $cve = $e->respond(new RequestContext('GET', '/checkout/order-pay/45812', 'pay_for_order=true&key=x', [], ''));
        self::assertTrue($cve === null || strpos($cve->body, 'wc_stripe_params') === false, 'no IDOR page off-store');

        $exploit = $e->respond(new RequestContext('POST', '/wp-json/wp/v2/users', '', ['X-WCPAY-PLATFORM-CHECKOUT-USER' => '1'], '{}'));
        self::assertTrue($exploit === null || $exploit->status !== 201, 'no admin-create off-store');

        // /wp-json falls through to the BASE 344 index — present, but no wc/* namespaces.
        $index = $e->respond(new RequestContext('GET', '/wp-json'));
        self::assertNotNull($index, 'the base REST index still serves off-store');
        self::assertStringNotContainsString('"wc/store/v1"', $index->body, 'the base 344 index has no wc/*');
        self::assertStringNotContainsString('"wc/v3"', $index->body);
    }

    // --- 8. fingerprint sweep + version coherence -------------------------------------------------

    public function test_served_woo_bodies_are_fingerprint_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $denied = '/\b9\d{5}\b/';
        $checked = 0;
        for ($s = 0; $s <= 2000 && $checked < 12; $s++) {
            $e = $this->engine((string) $s);
            if (!$this->servedWooStore($e)) {
                continue;
            }
            $checked++;
            $bodies = [
                $e->respond(new RequestContext('GET', '/'))->body,
                $e->respond(new RequestContext('GET', '/wp-json'))->body,
                $e->respond(new RequestContext('GET', '/wp-json/wc/store/v1/products'))->body,
                $e->respond(new RequestContext('GET', '/wp-content/plugins/woocommerce/readme.txt'))->body,
                $e->respond(new RequestContext('GET', '/checkout/order-pay/45812', 'pay_for_order=1&key=x', [], ''))->body,
                $e->respond(new RequestContext('POST', '/wp-json/wp/v2/users', '', ['X-WCPAY-PLATFORM-CHECKOUT-USER' => '1'], '{}'))->body,
            ];
            foreach ($bodies as $i => $body) {
                self::assertSame([], $guard->scan($body), "seed {$s} woo body #{$i} carries a detector signature");
                self::assertDoesNotMatchRegularExpression($denied, $body, "seed {$s} woo body #{$i} trips \\b9\\d{5}\\b");
            }
        }
        self::assertGreaterThan(0, $checked, 'at least one store seed must be sampled');
    }

    public function test_readme_versions_are_cve_coherent(): void
    {
        // The payments/stripe plugin readmes render versions on the vulnerable side of their CVEs, so a
        // version fingerprinter and the exploit decoys agree on the same deploy.
        for ($s = 0; $s <= 400; $s++) {
            $p = PersonaIdentity::fromSeed($s);
            $payments = (string) $p->field('woocommerce.paymentsVersion');
            $stripe = (string) $p->field('woocommerce.stripeVersion');
            self::assertTrue(
                version_compare($payments, '4.8.0', '>=') && version_compare($payments, '5.6.1', '<='),
                "seed {$s}: payments {$payments} must be inside CVE-2023-28121 range 4.8.0–5.6.1"
            );
            self::assertTrue(
                version_compare($stripe, '7.4.0', '<='),
                "seed {$s}: stripe {$stripe} must be <= 7.4.0 (CVE-2023-34000 affected side)"
            );
        }
    }

    // --- compiled-artifact wiring falsifier -------------------------------------------------------

    public function test_compiled_index_and_rules_are_wired(): void
    {
        $b = $this->index()['routes']['GET /']['b'] ?? [];
        $store = array_values(array_filter($b, static function (array $bundle): bool {
            return ($bundle['pid'] ?? null) === 'route-woo-store';
        }));
        self::assertCount(1, $store, 'exactly one route-woo-store bundle folded into GET /');
        self::assertSame(8, (int) ($store[0]['w'] ?? 0), 'the capped-key fold forces w=8');
        self::assertSame(1, (int) ($store[0]['sig'] ?? 0), 'the store shell is sig=1 so GET / stays a root entry');

        $rules = require self::ATTACK;
        $gated = [];
        foreach ($rules as $r) {
            $id = (string) ($r['id'] ?? '');
            if (strpos($id, 'attack-woo-') === 0) {
                $gated[$id] = (string) ($r['persona_gate'] ?? '');
            }
        }
        self::assertCount(8, $gated, 'all eight woo attack rules compiled');
        foreach ($gated as $id => $gate) {
            self::assertSame('route-woo-store', $gate, "{$id} must be persona_gate route-woo-store");
        }
    }
}
