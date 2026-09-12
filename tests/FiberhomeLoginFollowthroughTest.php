<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

final class FiberhomeLoginFollowthroughTest extends TestCase
{
    private const PATH = '/boaform/admin/formLogin';
    private const ROUTE_KEY = 'POST /boaform/admin/formLogin';
    private const BENIGN_ID = 'attack-fiberhome-login';
    private const CRITICAL_ID = 'attack-fiberhome-27973';
    private const ATTACK_FILE = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const INDEX_FILE = __DIR__ . '/../resources/compiled/nuclei-index.full.php';

    private function config(string $mode = 'respond', bool $attackEmulation = true): Config
    {
        $config = new Config($mode);
        $config->gate = static function (RequestContext $request): bool { return true; };
        $config->personaSeed = static function (RequestContext $request): string { return 'fiberhome-login-test'; };
        $config->attackEmulation = $attackEmulation;
        $config->severityCeiling = 'critical';
        $config->decoySessionKey = str_repeat('f', 32);

        return $config;
    }

    private function engine(bool $attackEmulation = true): Honeypot
    {
        return Honeypot::default($this->config('respond', $attackEmulation));
    }

    /**
     * Replace the private emulator only inside an in-memory inverse-proof fixture; no production
     * injection seam is added.
     *
     * @param array<int,array<string,mixed>> $rules
     * @param array<string,mixed>|null $index
     */
    private function engineWith(array $rules, ?array $index = null): Honeypot
    {
        $engine = new Honeypot(new PhpArrayStore($index ?? require self::INDEX_FILE), $this->config());
        $property = new ReflectionProperty(Honeypot::class, 'attackEmulator');
        $property->setAccessible(true);
        $property->setValue($engine, new TemplateAttackEmulator($rules, [], null, null, [], null, str_repeat('f', 32)));

        return $engine;
    }

    /** @return array<int,array<string,mixed>> */
    private function rules(): array
    {
        return require self::ATTACK_FILE;
    }

    private function request(string $method = 'POST', string $path = self::PATH, ?string $body = 'username=operator&psd=opaque-one'): RequestContext
    {
        return new RequestContext($method, $path, '', [], $body);
    }

    public function test_compiled_pair_is_unique_ordered_and_byte_equivalent(): void
    {
        $rules = $this->rules();
        $ids = array_map(static function (array $rule): string { return (string) $rule['id']; }, $rules);
        self::assertSame(1, array_count_values($ids)[self::CRITICAL_ID] ?? 0);
        self::assertSame(1, array_count_values($ids)[self::BENIGN_ID] ?? 0);
        self::assertLessThan(array_search(self::BENIGN_ID, $ids, true), array_search(self::CRITICAL_ID, $ids, true));

        $benignRule = $rules[array_search(self::BENIGN_ID, $ids, true)];
        self::assertSame(['/boaform/admin/formlogin'], $benignRule['owns_path']);
        self::assertSame('info', $benignRule['severity']);

        $index = require self::INDEX_FILE;
        self::assertArrayHasKey(self::ROUTE_KEY, $index['routes']);
        self::assertSame('route-fiberhome-login', $index['routes'][self::ROUTE_KEY]['b'][0]['pid']);

        $attack = $this->engine(true)->respond($this->request());
        $route = $this->engine(false)->respond($this->request());
        self::assertNotNull($attack);
        self::assertNotNull($route);
        self::assertSame($attack->body, $route->body, 'the request-aware and exact-route renderers must not drift');
        self::assertSame($attack->headers['Content-Type'] ?? null, $route->headers['Content-Type'] ?? null);
        self::assertSame([], FingerprintGuard::fromPackage()->scanResponse($attack->body, $attack->headers));
        self::assertSame([], FingerprintGuard::fromPackage()->scanResponse($route->body, $route->headers));
    }

    /** @dataProvider benignBodies */
    public function test_benign_posts_serve_one_inert_failed_login_form(?string $body): void
    {
        $response = $this->engine()->respond($this->request('POST', self::PATH, $body));

        self::assertNotNull($response);
        self::assertNotNull($response->servedBy);
        self::assertSame(self::BENIGN_ID, $response->servedBy->ruleId);
        self::assertSame('info', $response->satisfies->highestSeverity);
        self::assertSame(200, $response->status);
        self::assertSame('text/html; charset=utf-8', $response->headers['Content-Type'] ?? null);
        self::assertStringContainsString('<title>Web User Login</title>', $response->body);
        self::assertStringContainsString('action="' . self::PATH . '"', $response->body);
        self::assertStringContainsString('name="username"', $response->body);
        self::assertStringContainsString('name="psd"', $response->body);
        self::assertStringContainsString('Authentication failed. Please try again.', $response->body);
    }

    /** @return array<string,array{0:string|null}> */
    public function benignBodies(): array
    {
        return [
            'ordinary' => ['username=operator&psd=opaque-one'],
            'empty' => [''],
            'missing' => [null],
            'missing fields' => ['unrelated=value'],
            'malformed' => ['%%%&&broken'],
        ];
    }

    public function test_emitted_form_can_be_followed_with_discovered_action_and_fields(): void
    {
        $first = $this->engine()->respond($this->request());
        self::assertNotNull($first);
        self::assertSame(1, preg_match('/<form[^>]+action="([^"]+)"/', $first->body, $action));
        self::assertSame(2, preg_match_all('/<input[^>]+name="([^"]+)"/', $first->body, $fields));
        self::assertSame(['username', 'psd'], $fields[1]);

        $body = rawurlencode($fields[1][0]) . '=fiberAliceOne&' . rawurlencode($fields[1][1]) . '=opaque-two';
        $second = $this->engine()->respond($this->request('POST', $action[1], $body));
        self::assertNotNull($second);
        self::assertSame(self::BENIGN_ID, $second->servedBy->ruleId);
        self::assertSame($first->body, $second->body);
    }

    public function test_unrelated_synthetic_credentials_are_not_reflected(): void
    {
        $first = $this->engine()->respond($this->request('POST', self::PATH, 'username=fiberAliceOne&psd=opaque-one'));
        $second = $this->engine()->respond($this->request('POST', self::PATH, 'username=fiberBobTwo&psd=opaque-two'));
        self::assertNotNull($first);
        self::assertNotNull($second);
        self::assertSame($first->body, $second->body);
        foreach (['fiberAliceOne', 'opaque-one', 'fiberBobTwo', 'opaque-two'] as $fragment) {
            self::assertStringNotContainsString($fragment, $first->body . $second->body);
        }
        self::assertSame([], FingerprintGuard::fromPackage()->scanResponse($first->body, $first->headers));
        self::assertSame([], FingerprintGuard::fromPackage()->scanResponse($second->body, $second->headers));
    }

    public function test_original_injection_keeps_the_critical_rule(): void
    {
        $response = $this->engine()->respond($this->request('POST', self::PATH, 'username=admin&telnet_enable=1;telnetd&psd=x'));

        self::assertNotNull($response);
        self::assertNotNull($response->servedBy);
        self::assertSame(self::CRITICAL_ID, $response->servedBy->ruleId);
        self::assertSame('critical', $response->satisfies->highestSeverity);
        self::assertStringNotContainsString('telnetd', $response->body);
        $benign = $this->engine()->respond($this->request());
        self::assertNotNull($benign);
        self::assertSame($benign->body, $response->body, 'original critical and new companion keep one canonical form');
    }

    /** @dataProvider ownedAliases */
    public function test_owned_aliases_reach_the_benign_companion(string $method, string $path): void
    {
        $response = $this->engine()->respond($this->request($method, $path));
        self::assertNotNull($response, $method . ' ' . $path);
        self::assertSame(self::BENIGN_ID, $response->servedBy->ruleId, $method . ' ' . $path);
    }

    /** @return array<string,array{0:string,1:string}> */
    public function ownedAliases(): array
    {
        return [
            'canonical' => ['POST', self::PATH],
            'lowercase method' => ['post', self::PATH],
            'mixed path' => ['POST', '/BOAForm/Admin/FormLogin'],
            'one slash' => ['POST', self::PATH . '/'],
            'two slashes' => ['POST', self::PATH . '//'],
            'three slashes mixed' => ['post', '/BOAFORM/ADMIN/FORMLOGIN///'],
        ];
    }

    public function test_suffix_prefixed_and_unrelated_paths_are_not_owned_by_the_companion(): void
    {
        $engine = $this->engine();
        foreach ([
            ['POST', self::PATH . 'Extra'],
            ['POST', '/prefix' . self::PATH],
            ['POST', '/unrelated/login'],
        ] as $case) {
            $response = $engine->respond($this->request($case[0], $case[1]));
            if ($response !== null && $response->servedBy !== null) {
                self::assertNotSame(self::BENIGN_ID, $response->servedBy->ruleId, $case[0] . ' ' . $case[1]);
            } else {
                self::assertNull($response, $case[0] . ' ' . $case[1]);
            }
        }
    }

    public function test_ordinary_get_and_head_on_the_canonical_path_miss(): void
    {
        $engine = $this->engine();
        self::assertNull($engine->respond($this->request('GET')));
        self::assertNull($engine->respond($this->request('HEAD')));
    }

    public function test_existing_method_discovery_applies_to_the_new_post_key(): void
    {
        $engine = $this->engine();
        foreach ([['OPTIONS', 204], ['TRACE', 405], ['PROPFIND', 405]] as $case) {
            $response = $engine->respond($this->request($case[0]));
            self::assertNotNull($response, $case[0]);
            self::assertSame($case[1], $response->status, $case[0]);
            self::assertSame('POST, OPTIONS', $response->headers['Allow'] ?? null, $case[0]);
        }
    }

    public function test_attack_emulation_off_keeps_the_static_route_only(): void
    {
        $engine = $this->engine(false);
        $benign = $engine->classify($this->request(), SiteProfile::empty());
        self::assertSame(Verdict::SCANNER_PROBE, $benign->classification);
        self::assertNotNull($benign->fakeHandle);
        self::assertSame(FakeHandle::KIND_ROUTE, $benign->fakeHandle->kind);
        self::assertSame(self::ROUTE_KEY, $benign->fakeHandle->key);

        $injection = $engine->respond($this->request('POST', self::PATH, 'username=x;telnetd&psd=y'));
        self::assertNotNull($injection);
        self::assertNotNull($injection->servedBy);
        self::assertSame(FakeHandle::KIND_ROUTE, $injection->servedBy->kind);
        self::assertSame(self::ROUTE_KEY, $injection->servedBy->key);
        self::assertSame('info', $injection->satisfies->highestSeverity);
    }

    public function test_response_authority_gates_preserve_existing_attack_and_route_semantics(): void
    {
        $request = $this->request();
        foreach (['detect', 'off'] as $mode) {
            self::assertNull(Honeypot::default($this->config($mode))->respond($request));
        }

        $closed = $this->config();
        $closed->gate = static function (RequestContext $r): bool { return false; };
        $attack = Honeypot::default($closed)->respond($request);
        self::assertNotNull($attack, 'the legacy facade intentionally treats an attack-class match as its own signal');
        self::assertSame(self::BENIGN_ID, $attack->servedBy->ruleId);

        $closedRoute = $this->config('respond', false);
        $closedRoute->gate = static function (RequestContext $r): bool { return false; };
        self::assertNull(Honeypot::default($closedRoute)->respond($request), 'the same closed gate suppresses the static route');

        $trusted = $this->config();
        $trusted->trustedBypass = static function (RequestContext $r): bool { return true; };
        self::assertNull(Honeypot::default($trusted)->respond($request));

        $killed = $this->config();
        $killed->killSwitch = static function (): bool { return true; };
        self::assertNull(Honeypot::default($killed)->respond($request));
    }

    public function test_small_seed_grid_stays_static_and_fingerprint_clean(): void
    {
        $bodies = [];
        $guard = FingerprintGuard::fromPackage();
        foreach (['fiber-grid-a', 'fiber-grid-b', 'fiber-grid-c', 'fiber-grid-d'] as $seed) {
            $config = $this->config();
            $config->personaSeed = static function (RequestContext $request) use ($seed): string { return $seed; };
            $response = Honeypot::default($config)->respond($this->request());
            self::assertNotNull($response, $seed);
            self::assertSame([], $guard->scanResponse($response->body, $response->headers), $seed);
            $bodies[] = $response->body;
        }
        self::assertCount(1, array_unique($bodies), 'the authored static form is seed-independent');
    }

    public function test_existing_caps_still_fail_closed(): void
    {
        $smallBody = $this->config();
        $smallBody->maxBodyBytes = 32;
        self::assertNull(Honeypot::default($smallBody)->respond($this->request()));

        $lowCeiling = $this->config();
        $lowCeiling->severityCeiling = 'low';
        self::assertNull(Honeypot::default($lowCeiling)->respond($this->request('POST', self::PATH, 'username=x;telnetd&psd=y')));
    }

    public function test_real_site_profile_guards_classification_and_synthesis(): void
    {
        $profile = new SiteProfile([], static function (string $method, string $path): bool {
            return strtoupper($method) === 'POST' && $path === self::PATH;
        });
        $engine = $this->engine();
        $verdict = $engine->classify($this->request(), $profile);
        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNull($verdict->fakeHandle);
        self::assertNull($engine->synthesize($verdict, $profile, 'fiberhome-login-test'));
    }

    public function test_owns_path_is_required_to_preserve_original_critical_precedence(): void
    {
        $rules = $this->rules();
        foreach ($rules as &$rule) {
            if (($rule['id'] ?? '') === self::BENIGN_ID) {
                unset($rule['owns_path']);
            }
        }
        unset($rule);

        $verdict = $this->engineWith($rules)->classify(
            $this->request('POST', self::PATH, 'username=x;telnetd&psd=y'),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ROUTE, $verdict->fakeHandle->kind);
        self::assertNotContains(self::CRITICAL_ID, $verdict->detection->templateIds());
    }

    public function test_exact_post_key_is_required_for_the_real_site_profile_guard(): void
    {
        $index = require self::INDEX_FILE;
        unset($index['routes'][self::ROUTE_KEY]);
        $engine = $this->engineWith($this->rules(), $index);
        $profile = new SiteProfile([], static function (string $method, string $path): bool {
            return strtoupper($method) === 'POST' && $path === self::PATH;
        });
        $verdict = $engine->classify($this->request(), $profile);

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(self::BENIGN_ID, $verdict->fakeHandle->ruleId);
    }

    public function test_synthetic_response_canary_would_break_the_no_reflection_contract(): void
    {
        $canary = 'fiberCredentialCanary';
        $rules = $this->rules();
        foreach ($rules as &$rule) {
            if (($rule['id'] ?? '') === self::BENIGN_ID) {
                $rule['response']['body'] = '<p>' . $canary . '</p>';
            }
        }
        unset($rule);

        $response = $this->engineWith($rules)->respond($this->request('POST', self::PATH, 'username=' . $canary));
        self::assertNotNull($response);
        self::assertStringContainsString($canary, $response->body, 'inverse fixture must expose the forbidden reflection canary');
    }

    public function test_bounded_sibling_form_submit_audit_uses_the_existing_owners(): void
    {
        $hnap = '<?xml version="1.0" encoding="utf-8"?>'
            . '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
            . '<Login xmlns="http://purenetworks.com/HNAP1/"><Action>login</Action>'
            . '<Username>Admin</Username><LoginPassword>DEADBEEF</LoginPassword><Captcha></Captcha>'
            . '</Login></soap:Body></soap:Envelope>';
        $phpPg = 'loginServer=' . rawurlencode(':5432:allow') . '&loginUsername=alice'
            . '&loginPassword_43535f929f0cc24fff91705ab9522864=opaque';

        $cases = [
            'webmin' => [new RequestContext('POST', '/session_login.cgi', '', [], 'user=operator&pass=opaque&page=/'), 'attack-webmin-session-login'],
            'jenkins' => [new RequestContext('POST', '/j_acegi_security_check', '', [], 'j_username=operator&j_password=opaque&from=%2F&Submit=Sign+in'), 'attack-jenkins-acegi-login'],
            'hnap' => [new RequestContext('POST', '/HNAP1', '', [], $hnap), 'attack-hnap-login'],
            'wordpress' => [new RequestContext('POST', '/wp-login.php', '', [], 'log=operator&pwd=opaque'), 'attack-wp-login'],
            'cpsrvd' => [new RequestContext('POST', '/login/', 'login_only=1', [], 'user=operator&pass=opaque'), 'attack-cpsrvd-login'],
            'phppgadmin' => [new RequestContext('POST', '/redirect.php', '', [], $phpPg), 'attack-phppgadmin-login'],
            'grafana' => [new RequestContext('POST', '/grafana/login', '', [], '{"user":"operator","password":"opaque"}'), 'attack-grafana-login'],
            'kibana' => [new RequestContext('POST', '/internal/security/login', '', ['kbn-xsrf' => 'true'], '{"providerType":"basic","params":{"username":"operator","password":"opaque"}}'), 'attack-kibana-login'],
            'phpmyadmin' => [new RequestContext('POST', '/phpmyadmin/index.php', '', [], 'pma_username=operator&pma_password=opaque'), 'attack-phpmyadmin-login'],
        ];

        $engine = $this->engine();
        foreach ($cases as $family => $case) {
            $response = $engine->respond($case[0]);
            self::assertNotNull($response, $family . ' intended form POST must remain reachable');
            self::assertNotNull($response->servedBy, $family);
            self::assertSame($case[1], $response->servedBy->ruleId, $family);
        }
    }
}
