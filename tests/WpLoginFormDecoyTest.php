<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\LoginDecoyField;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;

/**
 * The invisible login honeypot field (FP-0495). Pins the render<->detect seed agreement (the
 * make-or-break), the hidden-by-construction markup in BOTH login bodies, the per-render-seed
 * name derivation, the serve-neutral / no-reflection invariants, and the DIRECTIVE drift guard.
 */
final class WpLoginFormDecoyTest extends TestCase
{
    private const ATTACK = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const ROUTES = __DIR__ . '/../resources/compiled/funnypot-routes.php';

    /** The closed candidate list DIRECTIVE picks from — the field name is always one of these. */
    private const CLOSED_LIST = [
        'contact_phone', 'company_fax', 'alt_email', 'secondary_email', 'office_ext', 'mobile_alt',
    ];

    /** The compiled attack-97 login-error body (still carries {{...}} directives). */
    private function attackBody(): string
    {
        foreach (require self::ATTACK as $rule) {
            if (($rule['id'] ?? '') === 'attack-wp-login') {
                return (string) $rule['response']['body'];
            }
        }
        self::fail('attack-wp-login rule not found in compiled artifact');
    }

    /** The compiled route-50 login-page body (still carries {{...}} directives). */
    private function routeBody(): string
    {
        foreach (require self::ROUTES as $rule) {
            if (($rule['id'] ?? '') === 'route-wp-login') {
                return (string) $rule['body'];
            }
        }
        self::fail('route-wp-login rule not found in compiled artifact');
    }

    /** The decoy input's rendered name from a rendered body (matched by its stable `_ct` id). */
    private function decoyName(string $renderedBody): ?string
    {
        if (preg_match('/<input type="text" name="([^"]*)" id="[^"]*_ct"/', $renderedBody, $m) === 1) {
            return $m[1];
        }

        return null;
    }

    // --- field rendered + hidden in BOTH login bodies ----------------------------------------------

    public function test_field_rendered_hidden_in_both_login_bodies(): void
    {
        $renderer = new DirectiveRenderer(4242 /* identity seed — irrelevant to {{pick}} */);
        foreach (['route' => $this->routeBody(), 'attack' => $this->attackBody()] as $where => $body) {
            $html = $renderer->render($body, [], 12345);

            $name = $this->decoyName($html);
            self::assertNotNull($name, "{$where}: decoy input must be present");
            self::assertContains($name, self::CLOSED_LIST, "{$where}: name must be a closed-list member");

            // The decoy input is a plain empty text field, out of tab order + a11y tree + autofill.
            self::assertMatchesRegularExpression(
                '/<input type="text" name="' . preg_quote($name, '/') . '" id="[^"]*_ct" value="" tabindex="-1" autocomplete="off" aria-hidden="true" \/>/',
                $html,
                "{$where}: decoy input must be type=text, value empty, non-tabbable, aria-hidden, no autofill"
            );

            // The wrapper class is display:none — removed from render, tab order, a11y tree, autofill.
            self::assertMatchesRegularExpression(
                '/<style>\.[^{]*-field-row\{display:none\}<\/style>/',
                $html,
                "{$where}: a display:none rule must cover the decoy wrapper class"
            );
            self::assertStringContainsString('class="', $html);
            self::assertMatchesRegularExpression('/<p class="[^"]*-field-row">/', $html, "{$where}: decoy wrapper uses the field-row class");
        }
    }

    // --- name is off the RENDER seed, not the identity/persona seed (must-fix 3) --------------------

    public function test_name_varies_with_render_seed_but_not_with_identity_seed(): void
    {
        $body = $this->attackBody();

        // (a) Vary ONLY the identity (deploy/persona) seed at a FIXED render seed -> name UNCHANGED,
        //     because {{pick}} keys on the render seed, never identitySeed.
        $fixedRenderSeed = 777;
        $nameA = $this->decoyName((new DirectiveRenderer(1000))->render($body, [], $fixedRenderSeed));
        $nameB = $this->decoyName((new DirectiveRenderer(2000))->render($body, [], $fixedRenderSeed));
        self::assertNotNull($nameA);
        self::assertSame($nameA, $nameB, 'name must NOT change when only the identity seed varies');

        // (b) Vary the RENDER seed (two client IPs via seedFor) -> the name is not a fleet constant.
        $config = new Config('detect', null, 'matched-only', static function (RequestContext $r): string {
            return $r->headers['CIP'] ?? 'anon';
        });
        $renderer = new DirectiveRenderer();
        $names = [];
        for ($i = 1; $i <= 24; $i++) {
            $r = new RequestContext('POST', '/wp-login.php', '', ['CIP' => '203.0.113.' . $i], 'x=1', 'blog.example.com');
            $names[] = LoginDecoyField::expectedName($r, $config, $renderer);
        }
        foreach ($names as $n) {
            self::assertContains($n, self::CLOSED_LIST);
        }
        self::assertGreaterThan(1, count(array_unique($names)), 'name must vary across client-IP render seeds (not a fleet-wide constant)');
    }

    // --- render <-> detect agreement at one fixed seed (the make-or-break, must-fix 2) --------------

    public function test_render_matches_detect_at_one_seed_on_both_bodies(): void
    {
        // Default seedFor path (host|salt). One request -> one seed -> one name everywhere.
        $config = new Config();
        $r = new RequestContext('POST', '/wp-login.php', '', [], 'log=a&pwd=b', 'blog.acme.example');
        $seed = crc32($config->seedFor($r));
        $renderer = new DirectiveRenderer();

        $expected = LoginDecoyField::expectedName($r, $config, $renderer);
        self::assertContains($expected, self::CLOSED_LIST);

        $routeName = $this->decoyName($renderer->render($this->routeBody(), [], $seed));
        $attackName = $this->decoyName($renderer->render($this->attackBody(), [], $seed));

        self::assertSame($expected, $routeName, 'GET route body name must equal expectedName at the same seed');
        self::assertSame($expected, $attackName, 'POST error body name must equal expectedName at the same seed');

        // And a personaSeed-injected renderer (as prod uses for {{persona.*}}) resolves the SAME
        // decoy name — proving {{pick}} is decoupled from the deploy identity.
        $prodRenderer = new DirectiveRenderer(987654);
        self::assertSame($expected, $this->decoyName($prodRenderer->render($this->attackBody(), [], $seed)));
    }

    // --- filled -> tripped; empty / absent / only credentials -> not -------------------------------

    public function test_isTripped_true_only_when_the_decoy_is_filled(): void
    {
        $config = new Config();
        $r = new RequestContext('POST', '/wp-login.php', '', [], null, 'blog.acme.example');
        $name = LoginDecoyField::expectedName($r, $config);

        $filled = $this->withBody($r, 'log=admin&pwd=hunter2&' . $name . '=' . rawurlencode('bot@evil.test'));
        self::assertTrue(LoginDecoyField::isTripped($filled, $config), 'a non-empty decoy value is a scripted-bot signal');

        $emptyValue = $this->withBody($r, 'log=admin&pwd=hunter2&' . $name . '=');
        self::assertFalse(LoginDecoyField::isTripped($emptyValue, $config), 'an empty decoy value is a real user');

        $whitespace = $this->withBody($r, 'log=admin&pwd=hunter2&' . $name . '=' . rawurlencode('   '));
        self::assertFalse(LoginDecoyField::isTripped($whitespace, $config), 'a whitespace-only decoy value is not a signal');

        $credsOnly = $this->withBody($r, 'log=admin&pwd=hunter2');
        self::assertFalse(LoginDecoyField::isTripped($credsOnly, $config), 'a real login POST (only log/pwd) never trips');

        $emptyBody = $this->withBody($r, '');
        self::assertFalse(LoginDecoyField::isTripped($emptyBody, $config));

        $nullBody = $this->withBody($r, null);
        self::assertFalse(LoginDecoyField::isTripped($nullBody, $config));
    }

    // --- serve-neutral: the login page is byte-identical whether or not the decoy is filled ---------
    // --- and no reflection: a marker in the decoy value never reaches the served body/headers ------

    public function test_serve_neutral_and_no_reflection_over_the_real_corpus(): void
    {
        $engine = $this->fullEngine();
        $name = 'contact_phone'; // any list member; the served page never depends on the decoy at all
        $marker = 'ZZdecoyMARKER42ZZ';

        $without = $engine->respond(new RequestContext('POST', '/wp-login.php', '', [], 'log=root&pwd=x', 'blog.acme.example'));
        $with = $engine->respond(new RequestContext('POST', '/wp-login.php', '', [], 'log=root&pwd=x&' . $name . '=' . $marker, 'blog.acme.example'));

        self::assertNotNull($without);
        self::assertNotNull($with);
        self::assertSame($without->body, $with->body, 'the login page must be byte-identical whether or not the decoy is filled');
        self::assertSame($without->status, $with->status);
        self::assertStringNotContainsString($marker, $with->body, 'the submitted decoy value must never be reflected in the body');
        self::assertStringNotContainsString($marker, implode(' ', $with->headers), 'the submitted decoy value must never be reflected in a header');
    }

    // --- fingerprint-clean: no honeypot self-tell in the rendered login bodies ----------------------

    public function test_rendered_login_bodies_carry_no_honeypot_tell(): void
    {
        $renderer = new DirectiveRenderer(31337);
        foreach ([$this->routeBody(), $this->attackBody()] as $body) {
            $html = $renderer->render($body, [], 555);
            foreach (['honeypot', 'funnypot', 'trap', 'spam'] as $tell) {
                self::assertStringNotContainsStringIgnoringCase($tell, $html, "must not carry the '{$tell}' tell");
            }
            self::assertDoesNotMatchRegularExpression('/\bhp\b/i', $html, "must not carry a bare 'hp' token");
            self::assertDoesNotMatchRegularExpression('/\b9\d{5}\b/', $html, 'must not carry a bare 6-digit 9xxxxx token');
        }
    }

    // --- drift guard: both compiled bodies carry the DIRECTIVE single source of truth ---------------

    public function test_both_compiled_bodies_contain_the_directive(): void
    {
        self::assertStringContainsString(LoginDecoyField::DIRECTIVE, $this->routeBody(), 'route body must carry the shared DIRECTIVE');
        self::assertStringContainsString(LoginDecoyField::DIRECTIVE, $this->attackBody(), 'attack body must carry the shared DIRECTIVE');
    }

    // --- helpers -----------------------------------------------------------------------------------

    private function withBody(RequestContext $r, ?string $body): RequestContext
    {
        return new RequestContext($r->method, $r->path, $r->query, $r->headers, $body, $r->host, $r->scheme);
    }

    private function fullEngine(): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only', null, 'coherent', Style::MINIMAL,
            'high', 65536, 0, 0, true /* attackEmulation */
        );

        return new Honeypot($store, $config);
    }
}
