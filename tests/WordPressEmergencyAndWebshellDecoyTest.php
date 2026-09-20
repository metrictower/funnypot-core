<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0412 — Compromised-WordPress webshell family skins + emergency-reset decoy suite.
 *
 * Three surfaces, each driven over the artifact that actually runs it:
 *   A. attack/86-webshell.yaml `behavior: branch` — family-accurate bodies by filename, generic
 *      panel unchanged for every other path (compiled attack rules directly).
 *   B. attack/36-wp-emergency-post.yaml — owns_path POST credential oracle: captures user_login/pass
 *      as match-gates only, never reflected, no success/redirect (full engine over the real corpus,
 *      so the owns_path override runs on the true serve path).
 *   C. route/162-wp-emergency-script.yaml — the GET /emergency.php page carrying the real Plecost
 *      body[:512] witnesses + the three body_words + the persona-coherent admin username.
 *
 * INERT crux: nothing is executed and no submitted value is ever written or reflected.
 */
final class WordPressEmergencyAndWebshellDecoyTest extends TestCase
{
    private const ATTACK = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const INDEX = __DIR__ . '/../resources/compiled/nuclei-index.full.php';

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

    private function attackEmulate(string $method, string $path, string $query = '', ?string $body = null): ?object
    {
        return TemplateAttackEmulator::fromFile(self::ATTACK)
            ->emulate(new RequestContext($method, $path, $query, [], $body));
    }

    /** A full engine over the REAL corpus (owns_path override + route dressing on the true serve path). */
    private function fullEngine(bool $respondMode = false): Honeypot
    {
        $config = new Config(
            $respondMode ? 'respond' : 'detect',
            $respondMode ? static function (RequestContext $r): bool { return true; } : null,
            'matched-only', null, 'coherent', Style::MINIMAL,
            'critical', 65536, 0, 0, true /* attackEmulation */
        );

        return new Honeypot(new PhpArrayStore($this->index()), $config);
    }

    // --- A. Webshell family branching -------------------------------------------------------------

    public function test_wso_branch_serves_password_form_not_generic_panel(): void
    {
        $r = $this->attackEmulate('GET', '/wp-content/uploads/wso.php');
        self::assertNotNull($r);
        self::assertSame(['attack-webshell-panel'], $r->satisfies->templateIds());
        self::assertStringContainsString('name="pass"', $r->body, 'WSO unauth view is a bare password prompt');
        self::assertStringNotContainsString('uid=33(www-data)', $r->body, 'WSO branch must NOT be the generic panel');
    }

    public function test_c99_branch_retains_uid_and_self_string(): void
    {
        // Regression guard: TemplateEngineTest pins /c99.php -> uid=33(www-data); the c99 branch keeps it.
        $r = $this->attackEmulate('GET', '/c99.php');
        self::assertNotNull($r);
        self::assertStringContainsString('c99shell', $r->body);
        self::assertStringContainsString('uid=33(www-data)', $r->body);
    }

    public function test_b374k_branch_retains_uid_and_self_string(): void
    {
        $r = $this->attackEmulate('GET', '/b374k.php');
        self::assertNotNull($r);
        self::assertStringContainsString('b374k', $r->body);
        self::assertStringContainsString('uid=33(www-data)', $r->body);
    }

    public function test_generic_default_branch_is_unchanged(): void
    {
        // A non-family path (shell/cmd/alfa, uploads/*.php, cmd= params) has no case -> base panel.
        $shell = $this->attackEmulate('GET', '/shell.php');
        self::assertNotNull($shell);
        self::assertStringContainsString('uid=33(www-data)', $shell->body);

        $uploads = $this->attackEmulate('GET', '/wp-content/uploads/2023/07/wp-conf.php');
        self::assertNotNull($uploads);
        self::assertStringContainsString('uid=33(www-data)', $uploads->body);
    }

    // --- B. POST credential oracle ----------------------------------------------------------------

    public function test_post_oracle_wins_over_injection_archetypes_and_never_reflects(): void
    {
        // A SQLi-shaped pass= must reach the priority-36 oracle, not 50-sqli / ssti / cmdi.
        $inj = "user_login=admin&pass=x' OR '1'='1";

        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', '/emergency.php', '', [], $inj),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind);
        self::assertSame('attack-wp-emergency-post', $verdict->fakeHandle->ruleId);

        $r = $this->fullEngine(true)->respond(new RequestContext('POST', '/emergency.php', '', [], $inj));
        self::assertNotNull($r);
        self::assertSame(200, $r->status, 'oracle re-renders the reset page; no success 302');
        self::assertStringContainsString('Update Options', $r->body);
        self::assertStringContainsString('Your use of this script is at your sole risk', $r->body);
        // No reflection of the submitted password, no success message, no redirect.
        self::assertStringNotContainsString("x' OR '1'='1", $r->body, 'submitted pass must never be reflected');
        self::assertStringNotContainsString('updated', $r->body, 'no fake success message (app-tier)');
        self::assertArrayNotHasKey('Location', $r->headers, 'no redirect (app-tier decoy-session mint)');
    }

    public function test_post_oracle_matches_even_with_empty_body(): void
    {
        // Optional lookaheads: an empty/field-missing POST still matches (never falls through).
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', '/emergency.php', '', [], ''),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame('attack-wp-emergency-post', $verdict->fakeHandle->ruleId);
    }

    // --- C. Emergency GET page --------------------------------------------------------------------

    public function test_emergency_get_page_carries_witnesses_and_persona(): void
    {
        // REALISTIC (not MINIMAL): the enricher tier only runs above MINIMAL, where the terse
        // body_words fallback is served instead of the dressed page.
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only', null, 'coherent', Style::REALISTIC,
            'critical', 65536, 0, 0, true
        );
        $engine = new Honeypot(new PhpArrayStore($this->index()), $config);

        $r = $engine->respond(new RequestContext('GET', '/emergency.php'));
        self::assertNotNull($r);
        $body = $r->body;

        // The three rendered body_words (complementary Plecost witness set).
        self::assertStringContainsString('Your use of this script is at your sole risk', $body);
        self::assertStringContainsString('WordPress Administrator', $body);
        self::assertStringContainsString('Update Options', $body);

        // The real Plecost body[:512] matcher: both signatures inside the leading comment.
        $head = substr($body, 0, 512);
        self::assertStringContainsString('wp_hash_password(', $head);
        self::assertStringContainsString('update_user_meta(', $head);

        // Persona coherence: the preset username is the one deploy-stable admin identity.
        $admin = (string) PersonaIdentity::fromSeed($config->deploySeed())->field('user.admin.username');
        self::assertNotSame('', $admin);
        self::assertStringContainsString('value="' . $admin . '"', $body);
    }

    // --- Soft-404 sentinel (regression) -----------------------------------------------------------

    public function test_random_php_path_still_404s(): void
    {
        $engine = $this->fullEngine(true);
        $r = $engine->respond(new RequestContext('GET', '/zzz-' . bin2hex(random_bytes(6)) . '.php'));
        self::assertNull($r, 'a random non-existent *.php must fall through to a genuine 404');
    }
}
