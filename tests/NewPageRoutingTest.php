<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Crs\FingerprintGuard;
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
            'respond',                                                        // mode
            static function (RequestContext $r): bool { return true; },       // gate
            'matched-only',                                                   // pathScope
            static function (RequestContext $r): string { return 'fixed'; },  // personaSeed
            'coherent',                                                       // personaBreadth
            'realistic'                                                       // responseStyle
        ));
    }

    /** An inverter pinned to one persona seed and response style, for per-seed bundle coverage. */
    private function seededInverter(string $seed, string $style): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            $style
        ));
    }

    /**
     * Like seededInverter, but with the attack + param tiers live so a `/@fs/{path}` vite-fs
     * request dispatches its traversal-read disclosure (the param tier is off by default).
     */
    private function paramInverter(string $seed, string $style): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            $style,
            'high',
            65536,
            0,
            0,
            true // attackEmulation ⇒ builds the emulator, which loads the param buckets
        ));
    }

    /**
     * @dataProvider pages
     */
    public function test_new_page_routes_and_serves(string $path, int $status, string $marker, string $contentType): void
    {
        $inv = $this->inverter();

        self::assertTrue($inv->detect(new RequestContext('GET', $path))->matched, "{$path} must be detected");

        $resp = $inv->respond(new RequestContext('GET', $path));
        self::assertNotNull($resp, "{$path} must serve a fake");
        self::assertSame($status, $resp->status, "{$path} status");
        self::assertStringContainsString($marker, $resp->body, "{$path} must carry its marker");
        // Content-Type must match the request's file/endpoint type (a mismatch is a honeypot tell).
        self::assertSame($contentType, $resp->headers['Content-Type'] ?? null, "{$path} Content-Type");
    }

    /**
     * @return array<string, array{0:string,1:int,2:string,3:string}>
     */
    public static function pages(): array
    {
        return [
            'credentials.txt'   => ['/credentials.txt', 200, 'AWS_SECRET_ACCESS_KEY', 'text/plain; charset=utf-8'],
            'terraform.tfstate' => ['/terraform.tfstate', 200, '"terraform_version"', 'application/json'],
            'users.csv'         => ['/users.csv', 200, 'password_hash', 'text/csv; charset=utf-8'],
            'sql backup'        => ['/backup.sql', 200, 'CREATE TABLE', 'application/sql'],
            'basic-auth 401'    => ['/private/', 401, 'Authorization Required', 'text/html; charset=iso-8859-1'],
            'phpmyadmin login'  => ['/phpmyadmin/', 200, 'phpMyAdmin', 'text/html; charset=utf-8'],

            // AI-agent-config + MCP route pack. Config-file exposures (200) carry a scanner-shaped
            // key; the MCP/LLM endpoints answer with their vendor error status.
            'claude .claude.json'     => ['/.claude.json', 200, 'sk-ant-api03-', 'application/json'],
            'claude settings.json'    => ['/.claude/settings.json', 200, 'ANTHROPIC_API_KEY', 'application/json'],
            'claude desktop config'   => ['/claude_desktop_config.json', 200, 'GITHUB_PERSONAL_ACCESS_TOKEN', 'application/json'],
            'cursor mcp.json'         => ['/.cursor/mcp.json', 200, 'mcpServers', 'application/json'],
            'vscode mcp.json'         => ['/.vscode/mcp.json', 200, 'mcpServers', 'application/json'],
            'continue config.json'    => ['/.continue/config.json', 200, 'sk-ant-api03-', 'application/json'],
            'aider conf.yml'          => ['/.aider.conf.yml', 200, 'anthropic-api-key', 'text/yaml; charset=utf-8'],
            'copilot token endpoint'  => ['/copilot_internal/v2/token', 200, 'ghu_', 'application/json'],
            'openai models list'      => ['/openai/models', 200, '"object":"list"', 'application/json'],
            'mcp endpoint'            => ['/mcp', 400, 'jsonrpc', 'application/json'],
            'mcp endpoint (api)'      => ['/api/mcp', 400, 'jsonrpc', 'application/json'],
            'llm chat auth'           => ['/v1/chat', 401, 'invalid_request_error', 'application/json'],
            'llm completions auth'    => ['/v1/completions', 401, 'invalid_request_error', 'application/json'],
            'v1/models enrich'        => ['/v1/models', 200, '"owned_by":"openai"', 'application/json'],

            // Config-file disclosure pack (M8). Each leaks persona-seeded secrets and MUST serve the
            // Content-Type its file/endpoint type implies (a mismatch is a honeypot tell).
            'config.php'             => ['/config.php', 200, 'DB_PASSWORD', 'text/plain; charset=utf-8'],
            '.env.production'        => ['/.env.production', 200, 'AWS_SECRET_ACCESS_KEY', 'text/plain; charset=utf-8'],
            '.env.local'             => ['/.env.local', 200, 'AWS_SECRET_ACCESS_KEY', 'text/plain; charset=utf-8'],
            'secrets.json'           => ['/secrets.json', 200, 'secretKey', 'application/json'],
            'docker-compose.yml'     => ['/docker-compose.yml', 200, 'services:', 'text/yaml; charset=utf-8'],
            'application.properties' => ['/application.properties', 200, 'spring.datasource', 'text/plain; charset=utf-8'],

            // Log-file disclosure pack — brand-new log pages. The marker is a distinctive authored
            // string that is NOT one of the bundle's body words, so its presence proves the enriched
            // body served (not a minimal synth of the bare body words). Content-Type is the file's
            // real type (a mismatch is a honeypot tell).
            'wp debug.log'      => ['/wp-content/debug.log', 200, 'WordPress database error', 'text/plain; charset=utf-8'],
            'php error_log'     => ['/error_log', 200, 'Uncaught PDOException', 'text/plain; charset=utf-8'],
            'laravel.log (alt)' => ['/laravel.log', 200, 'QueryException', 'text/plain; charset=utf-8'],
            'nginx error.log'   => ['/var/log/nginx/error.log', 200, 'fastcgi://127.0.0.1:9000', 'text/plain; charset=utf-8'],
            'nginx access.log'  => ['/var/log/nginx/access.log', 200, 'CensysInspect', 'text/plain; charset=utf-8'],
            'apache error.log'  => ['/var/log/apache2/error.log', 200, 'AH00124', 'text/plain; charset=utf-8'],
            'apache access.log' => ['/var/log/apache2/access.log', 200, 'xmlrpc.php', 'text/plain; charset=utf-8'],
            'generic app.log'   => ['/app.log', 200, 'connection pool exhausted', 'text/plain; charset=utf-8'],
            'catalina.out'      => ['/catalina.out', 200, 'NullPointerException', 'text/plain; charset=utf-8'],
        ];
    }

    public function test_config_json_pages_stay_parseable(): void
    {
        // /secrets.json (a new page) and /settings.json (an enrich) both carry the JSON taunt as a
        // "_comment" field so the document still parses. Sweep seeds × styles and prove json_decode
        // returns a non-null array in every case — a broken taunt or an unescaped secret would fail.
        foreach (['/secrets.json', '/settings.json'] as $path) {
            foreach (['realistic', 'taunt'] as $style) {
                for ($seed = 0; $seed <= 30; $seed++) {
                    $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', $path));
                    self::assertNotNull($resp, "{$path} [{$style}] seed {$seed} must serve a fake");
                    self::assertSame('application/json', $resp->headers['Content-Type'] ?? null, "{$path} [{$style}] seed {$seed} Content-Type");
                    $decoded = json_decode($resp->body, true);
                    self::assertIsArray($decoded, "{$path} [{$style}] seed {$seed} must be a JSON object, got: " . $resp->body);
                }
            }
        }
    }

    public function test_config_secrets_are_coherent_across_surfaces(): void
    {
        // One host presents one identity: each disclosed secret must be byte-identical on every
        // surface that carries it, so two leaked files never contradict each other. AWS/Stripe/
        // SendGrid appear on the config pack AND the legacy sql/credentials surfaces (their
        // Stripe/SendGrid keys were migrated off standalone fake.* to the persona identity); the JWT
        // signing secret lives only on the config pack, so it is checked over the pages that carry it.
        $inv = $this->inverter();
        $cfg = ['/.env.production', '/.env.local', '/application.yml', '/application.properties', '/secrets.json', '/web.config', '/config.php'];
        $legacy = ['/install/froxlor.sql', '/credentials.txt', '/backup.sql'];
        $checks = [
            'aws' => ['re' => '/AKIA[A-Z2-7]{16}/', 'surfaces' => array_merge($cfg, $legacy)],
            'stripe' => ['re' => '/sk_live_[0-9a-zA-Z]{24}/', 'surfaces' => array_merge($cfg, $legacy)],
            'sendgrid' => ['re' => '/SG\.[0-9A-Za-z]{22}\.[0-9A-Za-z]{43}/', 'surfaces' => array_merge($cfg, $legacy)],
            'jwt' => ['re' => '/\b[0-9a-f]{64}\b/', 'surfaces' => $cfg],
        ];
        foreach ($checks as $label => $check) {
            $seen = [];
            foreach ($check['surfaces'] as $path) {
                $resp = $inv->respond(new RequestContext('GET', $path));
                self::assertNotNull($resp, "{$path} must serve a fake");
                self::assertSame(1, preg_match($check['re'], $resp->body, $m), "{$path} must disclose a {$label} secret");
                $seen[$m[0]] = true;
            }
            self::assertCount(1, $seen, "the {$label} secret must be identical across every surface that discloses it");
        }

        // The DB password is the SAME persona secret wherever it is disclosed, but in surface-specific
        // syntax (DATABASE_URL userinfo, DB_PASSWORD=, connectionString Password=, POSTGRES_PASSWORD:).
        // Extract per surface and require byte-identity — a hex-shape or non-persona password on any one
        // surface (the old credentials.txt tell) would contradict the rest.
        $dbPw = [
            '/.env.production'    => '/DB_PASSWORD=([A-Za-z0-9._~-]+)/',
            '/.env.local'         => '/DB_PASSWORD=([A-Za-z0-9._~-]+)/',
            '/settings.json'      => '#postgres://[^:@/]+:([A-Za-z0-9._~-]+)@#',
            '/web.config'         => '/Password=([A-Za-z0-9._~-]+);/',
            '/docker-compose.yml' => '/POSTGRES_PASSWORD:\s*([A-Za-z0-9._~-]+)/',
            '/credentials.txt'    => '#postgres://[^:@/]+:([A-Za-z0-9._~-]+)@#',
        ];
        $pwSeen = [];
        foreach ($dbPw as $path => $re) {
            $resp = $inv->respond(new RequestContext('GET', $path));
            self::assertNotNull($resp, "{$path} must serve a fake");
            self::assertSame(1, preg_match($re, $resp->body, $m), "{$path} must disclose a DB password: " . $resp->body);
            $pwSeen[$m[1]] = true;
        }
        self::assertCount(1, $pwSeen, 'the DB password must be identical across every surface that discloses it');
    }

    public function test_log_db_identity_is_coherent_with_config_pack(): void
    {
        // One host, one identity: the db name/user a leaked LOG discloses must be byte-identical to
        // what the M8 config pack discloses for the same seed — a log that named a different database
        // than /.env.production would betray the fabrication. The PHP error_log's PDOException carries
        // dbname=/user=; /.env.production carries DB_DATABASE=/DB_USERNAME=. Sweep seeds and require
        // equality on both fields.
        for ($seed = 0; $seed <= 20; $seed++) {
            $inv = $this->seededInverter((string) $seed, 'realistic');
            $log = $inv->respond(new RequestContext('GET', '/error_log'));
            $env = $inv->respond(new RequestContext('GET', '/.env.production'));
            self::assertNotNull($log, "seed {$seed}: /error_log must serve a fake");
            self::assertNotNull($env, "seed {$seed}: /.env.production must serve a fake");

            self::assertSame(1, preg_match('/dbname=([A-Za-z0-9_]+)/', $log->body, $ln), "seed {$seed}: error_log must leak a dbname");
            self::assertSame(1, preg_match('/DB_DATABASE=([A-Za-z0-9_]+)/', $env->body, $en), "seed {$seed}: .env.production must leak DB_DATABASE");
            self::assertSame($en[1], $ln[1], "seed {$seed}: the log and .env.production must name the SAME database");

            self::assertSame(1, preg_match('/ user=([A-Za-z0-9_]+)/', $log->body, $lu), "seed {$seed}: error_log must leak a db user");
            self::assertSame(1, preg_match('/DB_USERNAME=([A-Za-z0-9_]+)/', $env->body, $eu), "seed {$seed}: .env.production must leak DB_USERNAME");
            self::assertSame($eu[1], $lu[1], "seed {$seed}: the log and .env.production must name the SAME db user");
        }
    }

    public function test_log_access_log_serves_the_iceflow_coherent_body(): void
    {
        // /log/access.log's bundle carries BOTH the iceflow VPN witnesses and the generic
        // access-log-file needle. The dedicated iceflow enrich (priority 290) must win over
        // route-access-log (296) and serve the coherent IceFlow VPN body — never the generic
        // combined-access-log (Nmap/Censys/Googlebot) that would be an incoherent mix on an
        // ICEFLOW-witnessed path. `gw=vpn-gw01` is authored ONLY by the iceflow enrich (not a bundle
        // body word), so its presence proves the enrich served, not a minimal synth of `ICEFLOW VPN:`.
        foreach (['/log/access.log', '/log/vpn.log'] as $path) {
            $resp = $this->inverter()->respond(new RequestContext('GET', $path));
            self::assertNotNull($resp, "{$path} must serve a fake");
            self::assertSame(200, $resp->status, "{$path} status");
            self::assertSame('text/plain; charset=utf-8', $resp->headers['Content-Type'] ?? null, "{$path} Content-Type");
            self::assertStringContainsString('ICEFLOW VPN:', $resp->body, "{$path} must carry the iceflow body word");
            self::assertStringContainsString('gw=vpn-gw01', $resp->body, "{$path} must serve the enriched iceflow body, not a minimal synth");
            // The generic access-log body's scanner-UA lines must never appear on an iceflow path.
            self::assertStringNotContainsString('Nmap Scripting Engine', $resp->body, "{$path} must not serve the generic access-log body");
            self::assertStringNotContainsString('CensysInspect', $resp->body, "{$path} must not serve the generic access-log body");
        }
        // The header block carries the ICEFLOW witness via a real Server header (not only a synthetic).
        $resp = $this->inverter()->respond(new RequestContext('GET', '/log/access.log'));
        self::assertNotNull($resp);
        self::assertStringContainsString('ICEFLOW', (string) ($resp->headers['Server'] ?? ''), '/log/access.log Server header carries the ICEFLOW witness');
    }

    public function test_laravel_log_alt_uses_bound_parameter_sql(): void
    {
        // Real Laravel logs the QueryException SQL with the bound-parameter placeholder (`= ?`), never
        // the inlined binding value. The alt page (/laravel.log) must match the sibling enrich
        // (/storage/logs/laravel.log) exactly — a raw email in the SQL is invalid SQL and a format
        // the two disclosed logs would disagree on.
        for ($seed = 0; $seed <= 20; $seed++) {
            $inv = $this->seededInverter((string) $seed, 'realistic');
            $alt = $inv->respond(new RequestContext('GET', '/laravel.log'));
            $enrich = $inv->respond(new RequestContext('GET', '/storage/logs/laravel.log'));
            self::assertNotNull($alt, "seed {$seed}: /laravel.log must serve a fake");
            self::assertNotNull($enrich, "seed {$seed}: /storage/logs/laravel.log must serve a fake");

            self::assertSame(1, preg_match('/\(Connection: pgsql, SQL: ([^)]*)\)/', $alt->body, $am), "seed {$seed}: /laravel.log must log a QueryException SQL");
            self::assertSame(1, preg_match('/\(Connection: pgsql, SQL: ([^)]*)\)/', $enrich->body, $em), "seed {$seed}: /storage/logs/laravel.log must log a QueryException SQL");
            // Bound placeholder present, and no raw '@' (an inlined email) anywhere in the SQL clause.
            self::assertStringContainsString('= ?', $am[1], "seed {$seed}: /laravel.log SQL must use the bound placeholder");
            self::assertStringNotContainsString('@', $am[1], "seed {$seed}: /laravel.log SQL must not inline a raw email");
            // Both surfaces render the users-lookup SQL identically.
            self::assertSame($em[1], $am[1], "seed {$seed}: the two laravel logs must render the users-lookup SQL identically");
        }
    }

    public function test_wp_debug_log_db_name_differs_from_config_pack(): void
    {
        // A real host runs WordPress on its own MySQL database, separate from the pgsql app db the
        // config pack discloses. The WP debug.log's db name must therefore NEVER equal the
        // /.env.production DB_DATABASE for the same seed — the same name presented as MySQL on one
        // surface and Postgres on another would betray the fabrication. (Inverse of
        // test_log_db_identity_is_coherent_with_config_pack, which pins the pgsql-engine logs equal.)
        for ($seed = 0; $seed <= 60; $seed++) {
            $inv = $this->seededInverter((string) $seed, 'realistic');
            $wp = $inv->respond(new RequestContext('GET', '/wp-content/debug.log'));
            $env = $inv->respond(new RequestContext('GET', '/.env.production'));
            self::assertNotNull($wp, "seed {$seed}: /wp-content/debug.log must serve a fake");
            self::assertNotNull($env, "seed {$seed}: /.env.production must serve a fake");

            self::assertSame(1, preg_match("/Table '([A-Za-z0-9_]+)\\.wp_options'/", $wp->body, $wn), "seed {$seed}: wp debug.log must leak a db name");
            self::assertSame(1, preg_match('/DB_DATABASE=([A-Za-z0-9_]+)/', $env->body, $en), "seed {$seed}: .env.production must leak DB_DATABASE");
            self::assertNotSame($en[1], $wn[1], "seed {$seed}: the WordPress db name must differ from the pgsql app db name");
        }
    }

    public function test_migrated_aws_templates_render_persona_pair(): void
    {
        // The four legacy templates that shared a fingerprintable 6-value AWS `pick` now render the
        // persona identity's key pair: a well-formed AKIA id, never a doubled `AKIAAKIA` (which a
        // leftover literal `AKIA` prefix in front of the persona value would produce). Two of them
        // must agree on the pair, proving per-seed coherence replaced the shared constant.
        $inv = $this->inverter();
        $paths = ['/install/froxlor.sql', '/credentials.txt', '/terraform.tfstate', '/backup.sql'];
        $ids = [];
        foreach ($paths as $path) {
            $resp = $inv->respond(new RequestContext('GET', $path));
            self::assertNotNull($resp, "{$path} must serve a fake");
            self::assertSame(1, preg_match('/AKIA[A-Z2-7]{16}/', $resp->body, $m), "{$path} must render a persona AWS access key id");
            self::assertStringNotContainsString('AKIAAKIA', $resp->body, "{$path} must not double the AKIA prefix");
            $ids[$path] = $m[0];
        }
        self::assertSame($ids['/install/froxlor.sql'], $ids['/backup.sql'], 'migrated files share the persona AWS key for one seed');
    }

    public function test_config_js_never_serves_a_laravel_env(): void
    {
        // The /config.js route carries two bundles: a firebase config (application/javascript) and a
        // React runtime-env (application/octet-stream, REACT_APP_). A broad `env-` needle used to
        // hijack the react bundle to route-dotenv and serve a Laravel .env. Sweep seeds × styles and
        // require every response to be one of the two coherent bodies — NEVER a Laravel .env.
        $sawFirebase = false;
        $sawReact = false;
        foreach (['realistic', 'taunt'] as $style) {
            for ($seed = 0; $seed <= 40; $seed++) {
                $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', '/config.js'));
                self::assertNotNull($resp, "config.js [{$style}] seed {$seed} must serve a fake");
                self::assertStringNotContainsString('APP_DEBUG=', $resp->body, "config.js [{$style}] seed {$seed} must not serve a Laravel .env");
                $ct = $resp->headers['Content-Type'] ?? null;
                if ($ct === 'application/javascript') {
                    self::assertStringContainsString('firebaseConfig', $resp->body, "config.js [{$style}] seed {$seed} js body");
                    $sawFirebase = true;
                } elseif ($ct === 'application/octet-stream') {
                    self::assertStringContainsString('REACT_APP_', $resp->body, "config.js [{$style}] seed {$seed} react body");
                    $sawReact = true;
                } else {
                    self::fail("config.js [{$style}] seed {$seed} unexpected Content-Type: " . var_export($ct, true));
                }
            }
        }
        // The sweep must actually exercise both bundles, or it guards nothing.
        self::assertTrue($sawFirebase, 'sweep must land on the firebase config bundle');
        self::assertTrue($sawReact, 'sweep must land on the react runtime-env bundle');
    }

    public function test_firebase_ids_are_numeric_and_coherent(): void
    {
        // messagingSenderId must be an all-digit project number and the appId middle segment the SAME
        // digits (1:<senderId>:web:...) — hex letters in a digits-only field are a tell. A GCP project
        // number never has a leading zero, so the id must start 1-9. The react bundle's Sentry DSN
        // carries the same dec-encoded ids (org + project), pinned the same way.
        $sawFirebase = false;
        $sawSentry = false;
        for ($seed = 0; $seed <= 60; $seed++) {
            $resp = $this->seededInverter((string) $seed, 'realistic')->respond(new RequestContext('GET', '/config.js'));
            self::assertNotNull($resp);
            if (($resp->headers['Content-Type'] ?? null) === 'application/javascript') {
                $sawFirebase = true;
                self::assertSame(1, preg_match('/messagingSenderId: "(\d+)"/', $resp->body, $m), "seed {$seed} senderId must be all digits: " . $resp->body);
                self::assertTrue(ctype_digit($m[1]), "seed {$seed} senderId digits");
                self::assertNotSame('0', $m[1][0], "seed {$seed} senderId must not have a leading zero: " . $resp->body);
                self::assertStringContainsString('appId: "1:' . $m[1] . ':web:', $resp->body, "seed {$seed} appId must reuse the senderId");
            } else {
                // React runtime-env bundle: the Sentry DSN's org and project ids are numeric with no
                // leading zero (a real Sentry org/project id is a positive integer).
                self::assertSame(1, preg_match('#@o([0-9]+)\.ingest\.sentry\.io/([0-9]+)#', $resp->body, $m), "seed {$seed} sentry DSN shape: " . $resp->body);
                self::assertNotSame('0', $m[1][0], "seed {$seed} sentry org id must not have a leading zero: " . $resp->body);
                self::assertNotSame('0', $m[2][0], "seed {$seed} sentry project id must not have a leading zero: " . $resp->body);
                $sawSentry = true;
            }
        }
        self::assertTrue($sawFirebase, 'sweep must land on the firebase bundle at least once');
        self::assertTrue($sawSentry, 'sweep must land on the react/sentry bundle at least once');
    }

    public function test_env_local_is_a_distinct_local_config(): void
    {
        // /.env.local must be its own file — a LOCAL environment, not a byte clone of
        // /.env.production — while sharing the host's identity (same AWS pair, one host).
        $inv = $this->inverter();
        $prod = $inv->respond(new RequestContext('GET', '/.env.production'));
        $local = $inv->respond(new RequestContext('GET', '/.env.local'));
        self::assertNotNull($prod);
        self::assertNotNull($local);
        self::assertNotSame($prod->body, $local->body, '.env.local must not be byte-identical to .env.production');
        self::assertStringContainsString('APP_ENV=local', $local->body);
        self::assertStringContainsString('APP_DEBUG=true', $local->body);
        self::assertStringContainsString('DB_HOST=127.0.0.1', $local->body);
        self::assertStringContainsString('APP_ENV=production', $prod->body);
        self::assertSame(1, preg_match('/AKIA[A-Z2-7]{16}/', $prod->body, $a));
        self::assertSame(1, preg_match('/AKIA[A-Z2-7]{16}/', $local->body, $b));
        self::assertSame($a[0], $b[0], '.env.local and .env.production must share one AWS identity');
    }

    public function test_settings_json_is_a_shaped_indented_document(): void
    {
        // The VS Code settings.json must read as an authored file (nested lines indented), be a real
        // settings.json shape (top-level `launch` object), and stay valid JSON.
        $resp = $this->inverter()->respond(new RequestContext('GET', '/settings.json'));
        self::assertNotNull($resp);
        self::assertSame(1, preg_match('/\n[ ]{2,}"/', $resp->body), 'settings.json nested lines must be indented');
        self::assertStringContainsString('"launch"', $resp->body, 'settings.json must wrap the debug config in a launch object');
        self::assertIsArray(json_decode($resp->body, true), 'settings.json must be valid JSON');
    }

    public function test_database_url_round_trips_with_a_non_null_password(): void
    {
        // A '#' in the db password used to truncate the DATABASE_URL as an unencoded fragment marker.
        // Sweep seeds and require every rendered DATABASE_URL to parse with host + db path + a
        // non-null password whose userinfo is strictly URL-unreserved.
        foreach (['/docker-compose.yml', '/settings.json', '/credentials.txt'] as $path) {
            for ($seed = 0; $seed <= 60; $seed++) {
                $resp = $this->seededInverter((string) $seed, 'realistic')->respond(new RequestContext('GET', $path));
                self::assertNotNull($resp, "{$path} seed {$seed} must serve a fake");
                self::assertSame(1, preg_match('#postgres(?:ql)?://[^\s"\'<]+#', $resp->body, $m), "{$path} seed {$seed} must carry a DATABASE_URL");
                $url = $m[0];
                $parts = parse_url($url);
                self::assertIsArray($parts, "{$path} seed {$seed} DATABASE_URL must parse: {$url}");
                self::assertNotSame('', (string) ($parts['pass'] ?? ''), "{$path} seed {$seed} DATABASE_URL password must be non-null: {$url}");
                self::assertNotSame('', (string) ($parts['host'] ?? ''), "{$path} seed {$seed} DATABASE_URL must carry a host: {$url}");
                self::assertNotSame('', (string) ($parts['path'] ?? ''), "{$path} seed {$seed} DATABASE_URL must carry a db path: {$url}");
                $userinfo = (string) ($parts['user'] ?? '') . ':' . (string) ($parts['pass'] ?? '');
                self::assertSame(1, preg_match('#^[A-Za-z0-9._~-]+:[A-Za-z0-9._~-]+$#', $userinfo), "{$path} seed {$seed} userinfo must be URL-unreserved: {$url}");
            }
        }
    }

    public function test_yaml_configs_have_no_commented_out_scalars(): void
    {
        // A db password starting with '#' used to parse as a YAML comment (null value). With '#' out
        // of the alphabet, no rendered `key: value` line may begin its value with '#'. (The line-mode
        // taunt appends `# ...` comment lines, which have no `key:` and so never match.)
        foreach (['/docker-compose.yml', '/application.yml'] as $path) {
            foreach (['realistic', 'taunt'] as $style) {
                for ($seed = 0; $seed <= 60; $seed++) {
                    $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', $path));
                    self::assertNotNull($resp, "{$path} [{$style}] seed {$seed} must serve a fake");
                    self::assertSame(0, preg_match('/^\s*[\w.-]+: #/m', $resp->body), "{$path} [{$style}] seed {$seed} has a commented-out (leading '#') scalar: " . $resp->body);
                }
            }
        }
    }

    public function test_db_host_agrees_with_the_postgres_engine_claim(): void
    {
        // Every M8 config file hardcodes Postgres (pgsql/postgresql/:5432); the persona db.host must
        // never be named for another engine (mysql/mariadb), or the host contradicts the engine claim.
        $paths = ['/.env.production', '/.env.local', '/application.yml', '/application.properties', '/settings.json', '/web.config', '/config.php'];
        foreach ($paths as $path) {
            for ($seed = 0; $seed <= 60; $seed++) {
                $resp = $this->seededInverter((string) $seed, 'realistic')->respond(new RequestContext('GET', $path));
                self::assertNotNull($resp, "{$path} seed {$seed} must serve a fake");
                self::assertSame(0, preg_match('/\b(mysql|mariadb)\b/i', $resp->body), "{$path} seed {$seed} names a non-Postgres engine host while claiming Postgres: " . $resp->body);
            }
        }
    }

    public function test_disclosure_pages_carry_no_placeholder_host(): void
    {
        // registry.example.com and its kin read as a template stub; a dropped config on a real host
        // never uses an RFC-2606 example.com host. Guard the whole class on the disclosure pages.
        $inv = $this->inverter();
        $paths = ['/config.php', '/.env.production', '/.env.local', '/docker-compose.yml', '/credentials.txt', '/settings.json', '/web.config', '/application.yml', '/application.properties'];
        foreach ($paths as $path) {
            $resp = $inv->respond(new RequestContext('GET', $path));
            self::assertNotNull($resp, "{$path} must serve a fake");
            self::assertStringNotContainsString('example.com', $resp->body, "{$path} must not carry the placeholder example.com host");
        }
    }

    public function test_disclosure_pages_carry_no_denied_fingerprint_token(): void
    {
        // The gate's denylist (including the bare \b9\d{5}\b digit run) must hold for SERVED bodies,
        // not only compiled artifacts: a rendered secret that trips it would be classified as canned.
        // Render every disclosure surface across a wide seed sweep and require scan(body) empty — the
        // persona re-roll is what keeps the boundary-prone keys clean.
        $guard = FingerprintGuard::fromPackage();
        // Every disclosure surface that carries a seed-derived hex/digit island — including the ones
        // whose RDS/ElastiCache host fragments were the \b9\d{5}\b hazard (wp-config, terraform, and
        // the vite-fs traversal-read bodies). A future hex island on any of these regresses here.
        $paths = [
            '/config.php', '/.env.production', '/.env.local', '/secrets.json', '/docker-compose.yml',
            '/application.properties', '/application.yml', '/settings.json', '/web.config', '/config.js',
            '/credentials.txt', '/backup.sql', '/install/froxlor.sql',
            '/wp-config.php-backup', '/terraform.tfstate', '/.terraform/terraform.tfstate', '/infra/terraform.tfstate',
            // Log-file disclosure pack — enrich surfaces (dressed corpus bundles). Logs are dense with
            // timestamps/sizes/PIDs/line numbers, so the \b9\d{5}\b run is the acute hazard here.
            '/npm-debug.log', '/storage/logs/laravel.log', '/firebase-debug.log', '/var/log/debug.log',
            '/development.log', '/production.log', '/access.log',
            // IceFlow VPN log enrich — /log/access.log (iceflow wins over the generic access-log there)
            // plus a pure-iceflow path; both render the dec:4/dec:5 byte-counter islands and the IP pool.
            '/log/access.log', '/log/vpn.log',
            // Log pack — brand-new log pages. One path per rule renders the whole body; aliases are
            // byte-identical. Covers the dec:5 worker/pid/port islands and the client-IP pools.
            '/wp-content/debug.log', '/error_log', '/laravel.log',
            '/var/log/nginx/error.log', '/var/log/nginx/access.log',
            '/var/log/apache2/error.log', '/var/log/apache2/access.log', '/app.log', '/catalina.out',
        ];
        // The vite-fs `/@fs/{path}` param route serves per-target disclosure bodies (its own RDS/cache
        // host islands live in the .env and wp-config.php loot targets), so exercise those too.
        $paramPaths = ['/@fs/var/www/app/.env', '/@fs/var/www/html/wp-config.php'];
        for ($seed = 0; $seed <= 200; $seed++) {
            $inv = $this->seededInverter((string) $seed, 'realistic');
            foreach ($paths as $path) {
                $resp = $inv->respond(new RequestContext('GET', $path));
                self::assertNotNull($resp, "{$path} seed {$seed} must serve a fake");
                $hits = $guard->scan($resp->body);
                self::assertSame([], $hits, "{$path} seed {$seed} leaks a denied fingerprint token (" . implode(',', $hits) . "): " . $resp->body);
            }
            $paramInv = $this->paramInverter((string) $seed, 'realistic');
            foreach ($paramPaths as $path) {
                $resp = $paramInv->respond(new RequestContext('GET', $path));
                self::assertNotNull($resp, "{$path} seed {$seed} must serve a fake");
                $hits = $guard->scan($resp->body);
                self::assertSame([], $hits, "{$path} seed {$seed} leaks a denied fingerprint token (" . implode(',', $hits) . "): " . $resp->body);
            }
        }
    }

    public function test_v1_models_enrich_serves_openai_list(): void
    {
        // The corpus routes /v1/models to several OpenAI-compatible bundles; the enrich dresses the
        // selected one with a full OpenAI-shaped list. The "owned_by":"openai" marker is unique to
        // that body (minimal synth would emit only the "object":"list" body words), so its presence
        // proves the enrich rule — not a plain fallback — served the response.
        $resp = $this->inverter()->respond(new RequestContext('GET', '/v1/models'));

        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('"object":"list"', $resp->body);
        self::assertStringContainsString('"owned_by":"openai"', $resp->body);
    }

    public function test_v1_models_every_bundle_serves_valid_json(): void
    {
        // /v1/models is served by THREE candidate bundles (xinference, jan, vllm); the persona seed
        // picks one per host. The compact 260 body dresses xinference/jan, but vllm witnesses on
        // spaced-JSON regexes 260 can't carry — without 261 its minimal synth emitted an
        // unterminated, invalid-JSON fragment served as application/json (a definite tell). This
        // sweeps enough seeds to land on all three bundles and asserts EVERY one serves parseable,
        // non-empty JSON with the OpenAI list shape, in both realistic and taunt styles.
        $sawVllm = false;   // spaced-JSON vLLM body (the bundle 261 fixes)
        $sawOpenai = false; // compact OpenAI body (xinference/jan, from 260)

        foreach (['realistic', 'taunt'] as $style) {
            for ($seed = 0; $seed <= 60; $seed++) {
                $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', '/v1/models'));

                self::assertNotNull($resp, "seed {$seed} [{$style}] must serve a fake");
                self::assertSame(200, $resp->status, "seed {$seed} [{$style}] status");
                self::assertSame('application/json', $resp->headers['Content-Type'] ?? null, "seed {$seed} [{$style}] Content-Type");
                self::assertNotSame('', $resp->body, "seed {$seed} [{$style}] body must be non-empty");

                $decoded = json_decode($resp->body, true);
                self::assertNotNull(
                    $decoded,
                    "seed {$seed} [{$style}] must be valid JSON, got: " . $resp->body
                );
                self::assertIsArray($decoded, "seed {$seed} [{$style}] JSON must be an object");
                self::assertSame('list', $decoded['object'] ?? null, "seed {$seed} [{$style}] must carry object:list");

                if (strpos($resp->body, '"owned_by" : "vllm"') !== false) {
                    $sawVllm = true;
                }
                if (strpos($resp->body, '"owned_by":"openai"') !== false) {
                    $sawOpenai = true;
                }
            }
        }

        // The sweep must actually exercise both bundle families, or it guards nothing.
        self::assertTrue($sawVllm, 'sweep must land on the vllm bundle (the one 261 fixes)');
        self::assertTrue($sawOpenai, 'sweep must land on the compact OpenAI (xinference/jan) bundle');
    }

    public function test_ai_key_is_coherent_across_surfaces(): void
    {
        // One host presents one identity: the same seed must render the SAME Anthropic key in every
        // file that carries it, so two leaked configs never contradict each other.
        $inv = $this->inverter();
        $claude = $inv->respond(new RequestContext('GET', '/.claude.json'));
        $continue = $inv->respond(new RequestContext('GET', '/.continue/config.json'));

        self::assertNotNull($claude);
        self::assertNotNull($continue);
        self::assertSame(1, preg_match('/sk-ant-api03-[A-Za-z0-9_-]{93}AA/', $claude->body, $a));
        self::assertSame(1, preg_match('/sk-ant-api03-[A-Za-z0-9_-]{93}AA/', $continue->body, $b));
        self::assertSame($a[0], $b[0], 'same seed => identical Anthropic key across surfaces');
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
