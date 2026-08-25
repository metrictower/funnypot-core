<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Ai\ModelCatalog;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

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

    /** Like seededInverter, but with an explicit severity ceiling (default is 'high'). */
    private function seededInverterCeiling(string $seed, string $style, string $ceiling): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            $style,
            $ceiling
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

            // Ollama GET recon surface — brand-new pages a scanner hits to fingerprint a running rig.
            // /api/version is a static daemon banner; /api/tags + /api/ps are catalog-derived (compiled
            // by `funnypot compile-ai` into templates/generated/, one source of truth in ModelCatalog).
            'ollama version'          => ['/api/version', 200, '"version"', 'application/json; charset=utf-8'],
            'ollama tags'             => ['/api/tags', 200, 'kimi-k3:2.8t', 'application/json; charset=utf-8'],
            'ollama ps'               => ['/api/ps', 200, '"size_vram"', 'application/json; charset=utf-8'],

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

            // Framework debug-page disclosure pack — enrich rules that dress a corpus-routed
            // detection endpoint (Ignition / Symfony profiler / Spring actuator / Telescope). The
            // marker is a distinctive authored string that is NOT one of the bundle's body words, so
            // its presence proves the enriched body served (not a minimal synth of the bare bw), and
            // the Content-Type is exactly what the endpoint's real content type implies (a mismatch
            // is a honeypot tell). JSON pages are application/json (NOT the vnd.spring-boot media
            // type — it lacks the `application/json` substring the header-word check needs). The
            // Werkzeug /console enrich fires only on one of three co-bundles, so it is swept
            // separately (test_werkzeug_console_enrich_serves_locked_page). The bare /actuator index
            // is intentionally NOT enriched (its needle collides with the jolokia-xxe bundle).
            'ignition health-check' => ['/_ignition/health-check', 200, '"can_execute_commands": true', 'application/json'],
            'ignition logs'         => ['/_ignition/logs', 200, 'QueryException', 'application/json'],
            'symfony profiler'      => ['/_profiler/empty/search/results', 200, 'sf-search-results', 'text/html; charset=utf-8'],
            'laravel telescope'     => ['/telescope/requests', 200, '<div id="telescope">', 'text/html; charset=utf-8'],
            'actuator /env'         => ['/actuator/env', 200, 'spring.datasource.password', 'application/json'],
            'actuator /health'      => ['/actuator/health', 200, 'PostgreSQL', 'application/json'],
            'actuator /mappings'    => ['/actuator/mappings', 200, '/api/users', 'application/json'],
            'actuator /info'        => ['/actuator/info', 200, 'Eclipse Adoptium', 'application/json'],
            'actuator /beans'       => ['/actuator/beans', 200, 'HikariDataSource', 'application/json'],
            'actuator /loggers'     => ['/actuator/loggers', 200, 'effectiveLevel', 'application/json'],
            'actuator /threaddump'  => ['/actuator/threaddump', 200, 'RUNNABLE', 'application/json'],
            'actuator /configprops' => ['/actuator/configprops', 200, 'org.postgresql.Driver', 'application/json'],

            // API-recon / API-docs disclosure pack. Each marker is a distinctive authored string that
            // is NOT one of the bundle's body words, so its presence proves the authored (enrich or
            // new_page) body served rather than a minimal synth of the bare body words. Content-Type is
            // exactly the endpoint's real type (a mismatch is a honeypot tell). /openapi.json and POST
            // /graphql are seed- or ceiling-dependent and are exercised in their own per-seed tests.
            'openapi/swagger doc'   => ['/swagger.json', 200, '"securitySchemes"', 'application/json'],
            'swagger 2.0 apidocs'   => ['/v2/api-docs', 200, '"securityDefinitions"', 'application/json'],
            'openapi yaml'          => ['/openapi.yaml', 200, 'bearerFormat: JWT', 'text/yaml; charset=utf-8'],
            'swagger-ui html'       => ['/swagger-ui.html', 200, 'deepLinking', 'text/html; charset=utf-8'],
            'wp-json rest index'    => ['/wp-json', 200, 'wp-site-health', 'application/json'],
            'api/v2 rest index'     => ['/api/v2', 200, '"documentation"', 'application/json'],
            'security.txt'          => ['/.well-known/security.txt', 200, 'Preferred-Languages', 'text/plain; charset=utf-8'],
            'ai-plugin manifest'    => ['/.well-known/ai-plugin.json', 200, 'legal_info_url', 'application/json'],
            'openapi redoc'         => ['/openapi', 200, 'Redoc.init', 'text/html; charset=utf-8'],
            // Sibling paths the path-blind findRule enriches to a single bundle: /api/docs always
            // serves the ReDoc shell; /security.txt mirrors the .well-known security.txt file.
            'api/docs redoc'        => ['/api/docs', 200, 'Redoc.init', 'text/html; charset=utf-8'],
            'security.txt (root)'   => ['/security.txt', 200, 'Preferred-Languages', 'text/plain; charset=utf-8'],

            // Management / admin-panel disclosure pack — brand-new version/health/login pages (no nuclei
            // template at these paths). Each marker is a distinctive authored string that is NOT one of
            // the synth bundle's body words, so its presence proves the authored body served (not a
            // minimal synth of the bare body words). Content-Type is exactly the endpoint's real type (a
            // mismatch is a honeypot tell): phpMyAdmin ChangeLog/README are text/plain, the doc index and
            // the login shells are text/html, the Grafana health + Jenkins API roots are application/json.
            'phpmyadmin ChangeLog'  => ['/phpmyadmin/ChangeLog', 200, '5.2.1 (2023-02-07)', 'text/plain; charset=utf-8'],
            'phpmyadmin README'     => ['/phpmyadmin/README', 200, 'Version 5.2.1', 'text/plain; charset=utf-8'],
            'phpmyadmin doc index'  => ['/phpmyadmin/doc/html/index.html', 200, 'phpMyAdmin 5.2.1 documentation', 'text/html; charset=utf-8'],
            'grafana health'        => ['/api/health', 200, '"database": "ok"', 'application/json'],
            'grafana login'         => ['/grafana/', 200, 'window.grafanaBootData', 'text/html; charset=utf-8'],
            'grafana login (alt)'   => ['/grafana/login', 200, 'window.grafanaBootData', 'text/html; charset=utf-8'],
            'jenkins api/json'      => ['/api/json', 200, '"_class": "hudson.model.Hudson"', 'application/json'],
            'pgadmin login'         => ['/pgadmin4/', 200, 'Version 8.5', 'text/html; charset=utf-8'],
            'pgadmin login (alt)'   => ['/pgadmin4/login', 200, 'Version 8.5', 'text/html; charset=utf-8'],
            'cpanel login'          => ['/cpanel', 200, '<h1>cPanel</h1>', 'text/html; charset=utf-8'],
            'whm login'             => ['/whm', 200, 'Web Host Manager', 'text/html; charset=utf-8'],
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
            // Framework debug-page disclosure pack — enrich surfaces. Debug/actuator pages are dense
            // with ports, PIDs, byte counts, thread ids, versions and seed-derived tokens, so the
            // \b9\d{5}\b run is the acute hazard here. /console sweeps all three co-bundles.
            '/_ignition/health-check', '/_ignition/logs', '/_profiler/empty/search/results', '/console',
            '/telescope/requests', '/actuator/env', '/actuator/health', '/actuator/mappings',
            '/actuator/info', '/actuator/beans', '/actuator/loggers', '/actuator/threaddump',
            '/actuator/configprops',
            // API-recon / API-docs disclosure pack. OpenAPI docs carry ports, response codes, versions
            // and example ids (dec:5), so the \b9\d{5}\b run is the hazard here; /openapi.json is swept
            // across seeds so both its openapi and fastapi bundles are exercised. (POST /graphql is a
            // critical bundle above the default ceiling and is swept in its own ceiling=critical test.)
            '/swagger.json', '/api/swagger.json', '/v3/api-docs', '/api-docs', '/.well-known/openapi.json',
            '/v2/api-docs', '/openapi.yaml', '/swagger-ui.html', '/swagger-ui/index.html', '/swagger',
            '/api/__swagger__/', '/wp-json', '/api/v2', '/.well-known/security.txt',
            '/.well-known/ai-plugin.json', '/openapi', '/openapi.json',
            // Sibling paths the path-blind findRule also enriches (docs/redoc split between the redoc +
            // fastapi bundles; /api/docs is redoc-only; /security.txt mirrors the .well-known file).
            '/docs', '/redoc', '/api/docs', '/security.txt',
            // IoT / appliance disclosure pack — the enrich surfaces that serve at the default (high)
            // ceiling and route to exactly one bundle, so a fixed-seed sweep always renders THIS body.
            // Device pages carry MAC/serial/firmware/uptime islands, so \b9\d{5}\b is the acute hazard.
            // The 5 critical-severity device pages (deviceInfo/device.rsp/Sha1Account1/passwd/
            // api·deviceinfo) sit above this ceiling and are swept both-styles at the emulator in
            // EmulatorBreadthTest::test_iot_pack_bodies_carry_no_denied_fingerprint_token instead.
            '/Security/users', '/webapi/entry.cgi', '/cgi-bin/nobody/Machine.cgi', '/device/config',
            '/cgi-bin/', '/hp/device/DeviceInformation/View', '/PRESENTATION/HTML/TOP/PRTINFO.HTML',
            // Management / admin-panel disclosure pack — the enrich surfaces (single-bundle, so a fixed
            // seed always renders THIS body) plus every brand-new version/health/login page. Panel bodies
            // carry version strings, build/session ids and seed-derived commit hashes, so the \b9\d{5}\b
            // run is the acute hazard here.
            '/webmin/', '/phppgadmin/', '/app/kibana', '/jenkins/', '/api/frontend/settings',
            '/phpmyadmin/ChangeLog', '/phpmyadmin/README', '/phpmyadmin/doc/html/index.html',
            '/api/health', '/grafana/', '/grafana/login', '/api/json',
            '/pgadmin4/', '/pgadmin4/login', '/cpanel', '/whm',
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

    public function test_iot_disclosure_pages_serve_enriched_body_end_to_end(): void
    {
        // The IoT enrich must survive the WHOLE synthesizer, not only the emulator: the served
        // response must carry a distinctive authored marker that is NOT one of the bundle's body
        // words (proving the rich body served, not a minimal synth of the bare bw) AND the exact
        // Content-Type the device type demands (a mismatch would drop to minimal synth and is itself
        // a tell). These are the single-bundle routes, so a fixed seed always lands on the enrich; the
        // 5 critical-severity pages need the ceiling raised to serve at all (like the graphql enrich).
        // Multi-bundle routes (currentsetting/info.cgi/luci/getcfg/ExportAllSettings/LCDispatcher) are
        // seed-dependent in bundle selection and are proven at the bundle level in EmulatorBreadthTest.
        $cases = [
            ['/system/deviceInfo', '<model>DS-2CD2032-I</model>', 'application/xml'],
            ['/Security/users', '<userLevel>Administrator</userLevel>', 'application/xml'],
            ['/webapi/entry.cgi', '"api": "SYNO.Core.System"', 'application/json'],
            ['/cgi-bin/nobody/Machine.cgi', 'Product.Type=AVN80X', 'text/plain; charset=utf-8'],
            ['/device.rsp', '"uid": "admin"', 'application/json'],
            ['/api/system/deviceinfo', '<DeviceName>E5573s-320</DeviceName>', 'text/xml; charset=utf-8'],
            ['/current_config/Sha1Account1', 'IPC-HDBW23A0RN-ZS', 'application/octet-stream'],
            ['/device/config', 'Apollo VX20', 'application/json'],
            ['/current_config/passwd', 'id:name:passwd', 'text/plain; charset=utf-8'],
            ['/cgi-bin/', '<title>QNAP Turbo NAS</title>', 'text/html; charset=utf-8'],
            ['/hp/device/DeviceInformation/View', '<h1>Device Information</h1>', 'text/html; charset=utf-8'],
            ['/PRESENTATION/HTML/TOP/PRTINFO.HTML', 'SEIKO EPSON CORPORATION', 'text/html; charset=utf-8'],
        ];
        foreach (['realistic', 'taunt'] as $style) {
            for ($seed = 0; $seed <= 12; $seed++) {
                $inv = $this->seededInverterCeiling((string) $seed, $style, 'critical');
                foreach ($cases as [$path, $marker, $ct]) {
                    $resp = $inv->respond(new RequestContext('GET', $path));
                    self::assertNotNull($resp, "{$path} [{$style}] seed {$seed} must serve a fake");
                    self::assertSame(200, $resp->status, "{$path} [{$style}] seed {$seed} status");
                    self::assertSame($ct, $resp->headers['Content-Type'] ?? null, "{$path} [{$style}] seed {$seed} Content-Type must be exact");
                    self::assertStringContainsString($marker, $resp->body, "{$path} [{$style}] seed {$seed} must serve the enriched body, not a minimal synth");
                }
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

    public function test_ollama_tags_is_catalog_derived(): void
    {
        // The Ollama /api/tags page is compiled by `funnypot compile-ai` straight from the shared
        // ModelCatalog, so the served body must be byte-identical to json_encode($catalog->ollamaTags())
        // — one source of truth, never a hand-duplicated list. That guarantees the first model name and
        // the per-model quantization_level detail are present. /api/tags is also probed by a niche
        // Ollama-unauth corpus detection, so the page carries a heavy persona weight; assert the
        // catalog body serves across a wide seed sweep, not just the fixed seed.
        $expected = (string) json_encode(ModelCatalog::fromPackage()->ollamaTags(), JSON_UNESCAPED_SLASHES);
        for ($seed = 0; $seed <= 60; $seed++) {
            $resp = $this->seededInverter((string) $seed, 'realistic')->respond(new RequestContext('GET', '/api/tags'));
            self::assertNotNull($resp, "seed {$seed}: /api/tags must serve a fake");
            self::assertSame(200, $resp->status, "seed {$seed}: /api/tags status");
            self::assertSame('application/json; charset=utf-8', $resp->headers['Content-Type'] ?? null, "seed {$seed}: /api/tags Content-Type");
            self::assertSame($expected, $resp->body, "seed {$seed}: /api/tags must serve the exact ModelCatalog->ollamaTags() body");
            self::assertStringContainsString('kimi-k3:2.8t', $resp->body, "seed {$seed}: /api/tags must list the first catalog model");
            self::assertStringContainsString('"quantization_level"', $resp->body, "seed {$seed}: /api/tags must carry the quantization_level detail");
        }
    }

    public function test_ollama_ps_is_catalog_derived(): void
    {
        // /api/ps (the Ollama "running models" view) is compiled by `funnypot compile-ai` from the same
        // ModelCatalog, so the served body must be byte-identical to json_encode($catalog->ollamaPs()) —
        // one source of truth. That guarantees the loaded-model view carries the size_vram and expires_at
        // fields a real running daemon reports. /api/ps is a brand-new path (single bundle), so one check
        // is deterministic, but sweep a few seeds to match the tags coverage.
        $expected = (string) json_encode(ModelCatalog::fromPackage()->ollamaPs(), JSON_UNESCAPED_SLASHES);
        for ($seed = 0; $seed <= 20; $seed++) {
            $resp = $this->seededInverter((string) $seed, 'realistic')->respond(new RequestContext('GET', '/api/ps'));
            self::assertNotNull($resp, "seed {$seed}: /api/ps must serve a fake");
            self::assertSame(200, $resp->status, "seed {$seed}: /api/ps status");
            self::assertSame('application/json; charset=utf-8', $resp->headers['Content-Type'] ?? null, "seed {$seed}: /api/ps Content-Type");
            self::assertSame($expected, $resp->body, "seed {$seed}: /api/ps must serve the exact ModelCatalog->ollamaPs() body");
            self::assertStringContainsString('"size_vram"', $resp->body, "seed {$seed}: /api/ps must carry size_vram");
            self::assertStringContainsString('"expires_at"', $resp->body, "seed {$seed}: /api/ps must carry expires_at");
        }
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

    public function test_jenkins_surfaces_carry_the_x_jenkins_version_header(): void
    {
        // A scanner keys on the `X-Jenkins` response header to confirm Jenkins and lift its version.
        // Both the /jenkins/ dashboard enrich and the brand-new /api/json root must carry it end-to-end
        // (the emulator's headers survive the whole synthesizer), and both must report the SAME version
        // — one host, one controller. X-Jenkins-Session must be a valid RFC-4122 v4 UUID (real Jenkins
        // sets it from UUID.randomUUID()) and byte-identical across both surfaces (a per-boot constant),
        // and each surface must carry the X-Instance-Identity pubkey blob core always sends.
        $inv = $this->inverter();
        $sessions = [];
        $v4 = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/';
        foreach (['/jenkins/', '/api/json'] as $path) {
            $resp = $inv->respond(new RequestContext('GET', $path));
            self::assertNotNull($resp, "{$path} must serve a fake");
            self::assertSame('2.426.3', $resp->headers['X-Jenkins'] ?? null, "{$path} must carry the X-Jenkins version header");
            $session = $resp->headers['X-Jenkins-Session'] ?? '';
            self::assertSame(1, preg_match($v4, $session), "{$path} X-Jenkins-Session must be a valid v4 UUID, got '{$session}'");
            $sessions[] = $session;
            self::assertStringStartsWith('MIIBIjAN', $resp->headers['X-Instance-Identity'] ?? '', "{$path} must carry the X-Instance-Identity pubkey blob");
        }
        self::assertSame($sessions[0], $sessions[1], 'X-Jenkins-Session must be identical across /jenkins/ and /api/json (one controller, one boot)');
    }

    public function test_panel_disclosure_headers_are_tool_faithful(): void
    {
        // Webmin discloses its version in the Server banner (where real miniserv discloses it pre-auth),
        // not a page footer, and sets the static cookie-support probe `testing=1` (not a random session
        // token). cPanel/WHM are served by cpsrvd, whose Server banner both must carry, and /whm must be
        // WHM-branded — distinct from the /cpanel end-user login.
        $inv = $this->inverter();

        $webmin = $inv->respond(new RequestContext('GET', '/webmin/'));
        self::assertNotNull($webmin, '/webmin/ must serve a fake');
        self::assertSame('MiniServ/2.111', $webmin->headers['Server'] ?? null, '/webmin/ must disclose the version via the MiniServ Server banner');
        self::assertStringContainsString('testing=1', $webmin->headers['Set-Cookie'] ?? '', '/webmin/ must set the static testing=1 cookie-support probe');
        self::assertStringNotContainsString('Webmin 2.111', $webmin->body, '/webmin/ login page must not print a version/OS footer');

        foreach (['/cpanel', '/whm'] as $path) {
            $resp = $inv->respond(new RequestContext('GET', $path));
            self::assertNotNull($resp, "{$path} must serve a fake");
            self::assertSame('cpsrvd/11.118.0.13', $resp->headers['Server'] ?? null, "{$path} must carry the cpsrvd Server banner");
        }

        $whm = $inv->respond(new RequestContext('GET', '/whm'));
        self::assertNotNull($whm, '/whm must serve a fake');
        self::assertStringContainsString('Web Host Manager', $whm->body, '/whm must be WHM-branded');
        self::assertStringNotContainsString('<h1>cPanel</h1>', $whm->body, '/whm must not serve the cPanel wordmark');
    }

    public function test_panel_json_pages_stay_parseable(): void
    {
        // The Grafana settings/health and Jenkins API-root pages are served application/json, so each
        // must stay valid JSON across seeds × styles — a broken `_comment` taunt or an unescaped persona
        // value would fail json_decode and betray the fake.
        $paths = ['/api/frontend/settings', '/api/health', '/api/json'];
        foreach ($paths as $path) {
            foreach (['realistic', 'taunt'] as $style) {
                for ($seed = 0; $seed <= 30; $seed++) {
                    $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', $path));
                    self::assertNotNull($resp, "{$path} [{$style}] seed {$seed} must serve a fake");
                    self::assertSame('application/json', $resp->headers['Content-Type'] ?? null, "{$path} [{$style}] seed {$seed} Content-Type");
                    self::assertIsArray(json_decode($resp->body, true), "{$path} [{$style}] seed {$seed} must be a JSON object, got: " . $resp->body);
                }
            }
        }
    }

    public function test_grafana_build_is_coherent_across_its_surfaces(): void
    {
        // One host runs one Grafana build: the commit hash and version the unauthenticated /api/health
        // discloses must be byte-identical to what the /api/frontend/settings bootstrap config discloses
        // for the same seed — two surfaces reporting a different build would betray the fabrication. The
        // commit is a SHORT build hash (~10 hex), the length a real Grafana build reports — not a 40-char SHA.
        for ($seed = 0; $seed <= 30; $seed++) {
            $inv = $this->seededInverter((string) $seed, 'realistic');
            $health = $inv->respond(new RequestContext('GET', '/api/health'));
            $settings = $inv->respond(new RequestContext('GET', '/api/frontend/settings'));
            self::assertNotNull($health, "seed {$seed}: /api/health must serve a fake");
            self::assertNotNull($settings, "seed {$seed}: /api/frontend/settings must serve a fake");
            self::assertSame(1, preg_match('/"commit":\s*"([0-9a-f]{10})"/', $health->body, $hc), "seed {$seed}: /api/health must disclose a commit");
            self::assertSame(1, preg_match('/"commit":\s*"([0-9a-f]{10})"/', $settings->body, $sc), "seed {$seed}: /api/frontend/settings must disclose a commit");
            self::assertSame($sc[1], $hc[1], "seed {$seed}: the Grafana commit must match across /api/health and /api/frontend/settings");
        }
    }

    public function test_werkzeug_console_enrich_serves_locked_page(): void
    {
        // /console carries THREE co-bundles (websphere / selenium / werkzeug); the persona seed picks
        // one per host. The werkzeug enrich fires ONLY when the werkzeug bundle is picked. Sweep seeds
        // so the pick lands on it, and prove the enriched LOCKED console served: `The console is
        // locked` is authored ONLY by the enrich (not a bundle body word), so its presence rules out a
        // minimal synth of the bare `<h1>Interactive Console</h1>`. The console must never expose a
        // command surface or a PIN (zero-exec by construction).
        $sawWerkzeug = false;
        foreach (['realistic', 'taunt'] as $style) {
            for ($seed = 0; $seed <= 60; $seed++) {
                $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', '/console'));
                self::assertNotNull($resp, "/console [{$style}] seed {$seed} must serve a fake");
                if (strpos($resp->body, 'Interactive Console') === false) {
                    continue; // this seed picked the websphere/selenium co-bundle
                }
                $sawWerkzeug = true;
                self::assertSame('text/html; charset=utf-8', $resp->headers['Content-Type'] ?? null, "/console werkzeug [{$style}] seed {$seed} Content-Type");
                self::assertStringContainsString('The console is locked', $resp->body, "/console werkzeug [{$style}] seed {$seed} must serve the locked-console enrich, not a minimal synth");
                self::assertStringNotContainsString('__debugger__', $resp->body, "/console werkzeug must expose no command surface");
            }
        }
        self::assertTrue($sawWerkzeug, 'sweep must land on the werkzeug /console bundle at least once');
    }

    public function test_debug_json_pages_stay_parseable(): void
    {
        // Every JSON debug-page enrich must be valid JSON across seeds × styles — a broken taunt
        // (`_comment` field) or an unescaped persona value would fail json_decode. The Ignition logs
        // page carries no taunt (its `{"log_messages"` body word pins the opening brace), so under
        // taunt style it serves its plain body — still parseable.
        $paths = [
            '/_ignition/health-check', '/_ignition/logs',
            '/actuator/env', '/actuator/health', '/actuator/mappings', '/actuator/info',
            '/actuator/beans', '/actuator/loggers', '/actuator/threaddump', '/actuator/configprops',
        ];
        foreach ($paths as $path) {
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

    public function test_actuator_env_db_creds_are_coherent_with_config_pack(): void
    {
        // One host, one identity: the Postgres datasource the Spring Actuator /env dump discloses must
        // be byte-identical to what the M8 config pack (/.env.production) discloses for the same seed —
        // an actuator naming a different db/user/password than the .env would betray the fabrication.
        // The Ignition logs page names the same db user in its auth-failure line, pinned equal too.
        for ($seed = 0; $seed <= 30; $seed++) {
            $inv = $this->seededInverter((string) $seed, 'realistic');
            $env = $inv->respond(new RequestContext('GET', '/actuator/env'));
            $dotenv = $inv->respond(new RequestContext('GET', '/.env.production'));
            $logs = $inv->respond(new RequestContext('GET', '/_ignition/logs'));
            self::assertNotNull($env, "seed {$seed}: /actuator/env must serve a fake");
            self::assertNotNull($dotenv, "seed {$seed}: /.env.production must serve a fake");
            self::assertNotNull($logs, "seed {$seed}: /_ignition/logs must serve a fake");

            self::assertSame(1, preg_match('#jdbc:postgresql://[^:]+:5432/([A-Za-z0-9_]+)"#', $env->body, $en), "seed {$seed}: /actuator/env must disclose a db name");
            self::assertSame(1, preg_match('/DB_DATABASE=([A-Za-z0-9_]+)/', $dotenv->body, $dn), "seed {$seed}: /.env.production must disclose DB_DATABASE");
            self::assertSame($dn[1], $en[1], "seed {$seed}: actuator/env and .env.production must name the SAME database");

            self::assertSame(1, preg_match('/"spring.datasource.username": \{"value": "([A-Za-z0-9_]+)"\}/', $env->body, $eu), "seed {$seed}: /actuator/env must disclose a db user");
            self::assertSame(1, preg_match('/DB_USERNAME=([A-Za-z0-9_]+)/', $dotenv->body, $du), "seed {$seed}: /.env.production must disclose DB_USERNAME");
            self::assertSame($du[1], $eu[1], "seed {$seed}: actuator/env and .env.production must name the SAME db user");

            self::assertSame(1, preg_match('/"spring.datasource.password": \{"value": "([A-Za-z0-9._~-]+)"\}/', $env->body, $ep), "seed {$seed}: /actuator/env must disclose a db password");
            self::assertSame(1, preg_match('/DB_PASSWORD=([A-Za-z0-9._~-]+)/', $dotenv->body, $dp), "seed {$seed}: /.env.production must disclose DB_PASSWORD");
            self::assertSame($dp[1], $ep[1], "seed {$seed}: actuator/env and .env.production must share the SAME db password");

            // The Ignition auth-failure line names the same db user.
            self::assertSame(1, preg_match('/password authentication failed for user \\\\"([A-Za-z0-9_]+)\\\\"/', $logs->body, $lu), "seed {$seed}: /_ignition/logs must name the failing db user: " . $logs->body);
            self::assertSame($du[1], $lu[1], "seed {$seed}: the Ignition log and .env.production must name the SAME db user");
        }
    }

    public function test_apirecon_json_pages_stay_parseable(): void
    {
        // Every JSON page in the API-recon pack must be valid JSON across seeds × styles — a broken
        // taunt (`_comment` field after the lone opening `{`) or an unescaped persona value would fail
        // json_decode. Each is served application/json.
        $paths = [
            '/swagger.json', '/api/swagger.json', '/v3/api-docs', '/api-docs', '/.well-known/openapi.json',
            '/v2/api-docs', '/wp-json', '/api/v2', '/.well-known/ai-plugin.json',
        ];
        foreach ($paths as $path) {
            foreach (['realistic', 'taunt'] as $style) {
                for ($seed = 0; $seed <= 30; $seed++) {
                    $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', $path));
                    self::assertNotNull($resp, "{$path} [{$style}] seed {$seed} must serve a fake");
                    self::assertSame('application/json', $resp->headers['Content-Type'] ?? null, "{$path} [{$style}] seed {$seed} Content-Type");
                    self::assertIsArray(json_decode($resp->body, true), "{$path} [{$style}] seed {$seed} must be a JSON object, got: " . $resp->body);
                }
            }
        }
        // /openapi.json's `openapi` bundle serves the EXACT media type application/openapi+json — which
        // must still be valid JSON wherever the seed lands on it, in both styles.
        foreach (['realistic', 'taunt'] as $style) {
            for ($seed = 0; $seed <= 30; $seed++) {
                $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', '/openapi.json'));
                self::assertNotNull($resp, "/openapi.json [{$style}] seed {$seed} must serve a fake");
                if (strpos((string) ($resp->headers['Content-Type'] ?? ''), 'application/openapi+json') !== false) {
                    self::assertIsArray(json_decode($resp->body, true), "/openapi.json [{$style}] seed {$seed} openapi bundle must be valid JSON: " . $resp->body);
                }
            }
        }
    }

    public function test_openapi_yaml_parses_and_has_shape(): void
    {
        // /openapi.yaml must parse as YAML and read as a real OpenAPI 3.0 document (top-level openapi
        // version, a paths map, security schemes) in both styles — the line-mode taunt appends only
        // `#` comment lines, which YAML ignores.
        foreach (['realistic', 'taunt'] as $style) {
            for ($seed = 0; $seed <= 30; $seed++) {
                $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', '/openapi.yaml'));
                self::assertNotNull($resp, "/openapi.yaml [{$style}] seed {$seed} must serve a fake");
                self::assertSame('text/yaml; charset=utf-8', $resp->headers['Content-Type'] ?? null, "/openapi.yaml [{$style}] seed {$seed} Content-Type");
                $doc = Yaml::parse($resp->body);
                self::assertIsArray($doc, "/openapi.yaml [{$style}] seed {$seed} must parse as YAML: " . $resp->body);
                self::assertSame('3.0.3', $doc['openapi'] ?? null, "/openapi.yaml [{$style}] seed {$seed} must be OpenAPI 3.0.3");
                self::assertArrayHasKey('paths', $doc, "/openapi.yaml [{$style}] seed {$seed} must carry a paths map");
                self::assertArrayHasKey('securitySchemes', (array) ($doc['components'] ?? []), "/openapi.yaml [{$style}] seed {$seed} must carry securitySchemes");
            }
        }
    }

    public function test_apirecon_identity_is_coherent_across_surfaces(): void
    {
        // One host presents one identity: the OpenAPI doc's example bearer is a JWT-shaped token (real
        // HS256 header + seed-derived payload/signature), distinct from the raw HMAC signing secret the
        // config pack (Actuator /env) still discloses; the server URL's domain must match the
        // security.txt and ai-plugin contact domains; and the OpenAPI document must be byte-identical on
        // every surface that serves it.
        for ($seed = 0; $seed <= 30; $seed++) {
            $inv = $this->seededInverter((string) $seed, 'realistic');
            $swagger = $inv->respond(new RequestContext('GET', '/swagger.json'));
            $env = $inv->respond(new RequestContext('GET', '/actuator/env'));
            $sec = $inv->respond(new RequestContext('GET', '/.well-known/security.txt'));
            $ai = $inv->respond(new RequestContext('GET', '/.well-known/ai-plugin.json'));
            self::assertNotNull($swagger, "seed {$seed}: /swagger.json must serve a fake");
            self::assertNotNull($env, "seed {$seed}: /actuator/env must serve a fake");
            self::assertNotNull($sec, "seed {$seed}: /.well-known/security.txt must serve a fake");
            self::assertNotNull($ai, "seed {$seed}: /.well-known/ai-plugin.json must serve a fake");

            // The example Authorization value is a JWT-shaped token (three base64url segments, a real
            // HS256 header) matching the doc's `bearerFormat: JWT` — NOT the raw 64-hex HMAC signing
            // secret. The signing secret is still disclosed by the config pack (Actuator /env) as the
            // HS256 key, but the two are distinct kinds and must not be byte-equal.
            self::assertSame(1, preg_match('/Bearer (eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/', $swagger->body, $sj), "seed {$seed}: /swagger.json must leak a JWT-shaped example bearer token: " . $swagger->body);
            $seg = explode('.', $sj[1]);
            self::assertCount(3, $seg, "seed {$seed}: the example bearer must have three JWT segments");
            self::assertSame('{"alg":"HS256","typ":"JWT"}', base64_decode(strtr($seg[0], '-_', '+/')), "seed {$seed}: the JWT header segment must decode to an HS256 JWT header");
            self::assertSame(0, preg_match('/Bearer [0-9a-f]{64}\b/', $swagger->body), "seed {$seed}: the example bearer must not be the raw 64-hex signing secret");
            self::assertSame(1, preg_match('/"jwt.secret": \{"value": "([0-9a-f]{64})"\}/', $env->body, $ej), "seed {$seed}: /actuator/env must still disclose the 64-hex HS256 signing secret");
            self::assertNotSame($ej[1], $sj[1], "seed {$seed}: the JWT example token must not be the raw signing secret");

            // Server URL domain == security.txt contact domain == ai-plugin contact domain.
            self::assertSame(1, preg_match('#https://api\.([a-z0-9.-]+)/v2#', $swagger->body, $sh), "seed {$seed}: /swagger.json must carry an api.<domain> server URL");
            self::assertSame(1, preg_match('/Contact: mailto:[^@\s]+@([^\s]+)/', $sec->body, $ch), "seed {$seed}: security.txt must carry a mailto contact");
            self::assertSame($sh[1], $ch[1], "seed {$seed}: the OpenAPI server domain must match the security.txt contact domain");
            self::assertSame(1, preg_match('/"contact_email": "[^@"]+@([^"]+)"/', $ai->body, $ah), "seed {$seed}: ai-plugin must carry a contact_email");
            self::assertSame($sh[1], $ah[1], "seed {$seed}: the OpenAPI server domain must match the ai-plugin contact domain");

            // One OpenAPI document, byte-identical across every surface that serves it.
            foreach (['/api/swagger.json', '/v3/api-docs', '/api-docs', '/.well-known/openapi.json'] as $alias) {
                $a = $inv->respond(new RequestContext('GET', $alias));
                self::assertNotNull($a, "seed {$seed}: {$alias} must serve a fake");
                self::assertSame($swagger->body, $a->body, "seed {$seed}: {$alias} must be byte-identical to /swagger.json");
            }
            // /openapi.json, when its seed picks the openapi (JSON) bundle, serves the SAME document.
            $oj = $inv->respond(new RequestContext('GET', '/openapi.json'));
            self::assertNotNull($oj, "seed {$seed}: /openapi.json must serve a fake");
            if (strpos((string) ($oj->headers['Content-Type'] ?? ''), 'application/openapi+json') !== false) {
                self::assertSame($swagger->body, $oj->body, "seed {$seed}: /openapi.json (openapi bundle) must match /swagger.json");
            }
        }
    }

    public function test_openapi_json_serves_both_openapi_and_fastapi_bundles(): void
    {
        // /openapi.json carries TWO bundles: the `openapi` JSON doc (media type application/openapi+json,
        // NOT plain application/json) and the `fastapi-docs` Swagger-UI HTML shell (text/html). The
        // persona seed picks one per host. Sweep enough seeds to land on both and prove each fires its
        // own enrich with the EXACT Content-Type — a mismatch would drop the response to minimal synth.
        $sawOpenapi = false;
        $sawFastapi = false;
        foreach (['realistic', 'taunt'] as $style) {
            for ($seed = 0; $seed <= 60; $seed++) {
                $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', '/openapi.json'));
                self::assertNotNull($resp, "/openapi.json [{$style}] seed {$seed} must serve a fake");
                $ct = (string) ($resp->headers['Content-Type'] ?? '');
                if (strpos($ct, 'application/openapi+json') !== false) {
                    self::assertStringNotContainsString('text/html', $ct, "/openapi.json [{$style}] seed {$seed} openapi bundle must not be HTML");
                    self::assertStringContainsString('"securitySchemes"', $resp->body, "/openapi.json [{$style}] seed {$seed} must serve the OpenAPI doc, not a minimal synth");
                    self::assertIsArray(json_decode($resp->body, true), "/openapi.json [{$style}] seed {$seed} openapi bundle must be valid JSON");
                    $sawOpenapi = true;
                } elseif (strpos($ct, 'text/html') !== false) {
                    self::assertStringContainsString('FastAPI - Swagger UI', $resp->body, "/openapi.json [{$style}] seed {$seed} must serve the FastAPI docs shell");
                    self::assertStringContainsString('SwaggerUIBundle', $resp->body, "/openapi.json [{$style}] seed {$seed} must serve the Swagger-UI shell, not a minimal synth");
                    $sawFastapi = true;
                } else {
                    self::fail("/openapi.json [{$style}] seed {$seed} unexpected Content-Type: {$ct}");
                }
            }
        }
        self::assertTrue($sawOpenapi, 'sweep must land on the openapi (application/openapi+json) bundle');
        self::assertTrue($sawFastapi, 'sweep must land on the fastapi-docs (Swagger-UI HTML) bundle');
    }

    public function test_graphql_introspection_enrich_serves_only_above_the_default_ceiling(): void
    {
        // POST /graphql's wpgraphql bundle (CVE-2019-9880) is `critical` — ABOVE the default `high`
        // severity ceiling, so candidates() filters it before the persona pick and this enrich is
        // SUPPRESSED by default (POST /graphql falls to minimal synth of a co-bundle). It dresses the
        // bundle only when the operator raises the ceiling to `critical`. Under that ceiling, prove the
        // enrich fires (per-seed), is request-BLIND (the same canned body for any POST body), valid
        // JSON, exactly application/json, and carries no denied fingerprint token. Then prove the
        // default `high` ceiling never serves it.
        $guard = FingerprintGuard::fromPackage();
        $sawEnrich = false;
        foreach (['realistic', 'taunt'] as $style) {
            for ($seed = 0; $seed <= 60; $seed++) {
                $inv = $this->seededInverterCeiling((string) $seed, $style, 'critical');
                $resp = $inv->respond(new RequestContext('POST', '/graphql', '', [], '{"query":"{__schema{types{name}}}"}'));
                self::assertNotNull($resp, "POST /graphql [{$style}] seed {$seed} must serve a fake");
                if (strpos($resp->body, '"roles": ["administrator"]') === false) {
                    continue; // this seed picked a co-bundle (partial coverage by design)
                }
                $sawEnrich = true;
                self::assertSame('application/json', $resp->headers['Content-Type'] ?? null, "seed {$seed} graphql Content-Type must be exactly application/json");
                self::assertStringContainsString('__schema', $resp->body, "seed {$seed} must carry the introspection schema");
                self::assertIsArray(json_decode($resp->body, true), "seed {$seed} graphql body must be valid JSON: " . $resp->body);
                self::assertSame([], $guard->scan($resp->body), "seed {$seed} graphql body must carry no denied fingerprint token");
                // Request-blind: a different POST body returns the identical canned response.
                $other = $inv->respond(new RequestContext('POST', '/graphql', '', [], '{"query":"{ me { id } }"}'));
                self::assertNotNull($other);
                self::assertSame($resp->body, $other->body, "seed {$seed}: POST /graphql must be request-blind (same body for any query)");
            }
        }
        self::assertTrue($sawEnrich, 'a ceiling=critical sweep must land on the wpgraphql introspection bundle at least once');

        // Default `high` ceiling: the critical bundle is never a candidate, so the enrich never serves.
        for ($seed = 0; $seed <= 60; $seed++) {
            $resp = $this->seededInverter((string) $seed, 'realistic')->respond(new RequestContext('POST', '/graphql', '', [], '{"query":"{__schema{types{name}}}"}'));
            self::assertNotNull($resp, "seed {$seed}: POST /graphql must serve a fake");
            self::assertStringNotContainsString('"roles": ["administrator"]', $resp->body, "seed {$seed}: the critical graphql enrich must stay suppressed under the default high ceiling");
        }
    }

    public function test_docs_and_redoc_serve_one_of_the_two_enriched_shells(): void
    {
        // findRule is path-blind, so GET /docs and GET /redoc each carry the SAME two API-docs bundles
        // as /openapi.json's HTML side: the FastAPI Swagger-UI shell (SwaggerUIBundle) and the ReDoc
        // shell (__REDOC_EXPORT). The persona seed picks one per host. Sweep seeds and lock that every
        // response is one of the two enriched shells, served text/html — never a minimal synth or a
        // wrong Content-Type. (The swapped-path realism tell is documented in 331/332; scanners probe
        // both conventional paths and match either shell, so believability-to-scanners is unharmed.)
        foreach (['/docs', '/redoc'] as $path) {
            $sawSwagger = false;
            $sawRedoc = false;
            foreach (['realistic', 'taunt'] as $style) {
                for ($seed = 0; $seed <= 60; $seed++) {
                    $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', $path));
                    self::assertNotNull($resp, "{$path} [{$style}] seed {$seed} must serve a fake");
                    self::assertSame('text/html; charset=utf-8', $resp->headers['Content-Type'] ?? null, "{$path} [{$style}] seed {$seed} Content-Type");
                    if (strpos($resp->body, 'SwaggerUIBundle') !== false) {
                        self::assertStringContainsString('FastAPI - Swagger UI', $resp->body, "{$path} [{$style}] seed {$seed} must serve the full Swagger-UI shell");
                        $sawSwagger = true;
                    } elseif (strpos($resp->body, '__REDOC_EXPORT') !== false) {
                        self::assertStringContainsString('Redoc.init', $resp->body, "{$path} [{$style}] seed {$seed} must serve the full ReDoc shell");
                        $sawRedoc = true;
                    } else {
                        self::fail("{$path} [{$style}] seed {$seed} served neither enriched shell: " . $resp->body);
                    }
                }
            }
            self::assertTrue($sawSwagger, "{$path} sweep must land on the Swagger-UI shell at least once");
            self::assertTrue($sawRedoc, "{$path} sweep must land on the ReDoc shell at least once");
        }
    }

    public function test_wp_json_has_real_rest_root_shape(): void
    {
        // The /wp-json index must read as the genuine WP REST root: a JSON-number gmt_offset, a bare
        // tagline description (not the site title repeated), and every routes entry carrying endpoints
        // plus an _links.self href — with every declared namespace owning at least one route.
        foreach (['realistic', 'taunt'] as $style) {
            for ($seed = 0; $seed <= 30; $seed++) {
                $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', '/wp-json'));
                self::assertNotNull($resp, "/wp-json [{$style}] seed {$seed} must serve a fake");
                $doc = json_decode($resp->body, true);
                self::assertIsArray($doc, "/wp-json [{$style}] seed {$seed} must be valid JSON: " . $resp->body);
                self::assertIsInt($doc['gmt_offset'] ?? null, "/wp-json [{$style}] seed {$seed} gmt_offset must be a JSON number: " . $resp->body);
                self::assertSame('Just another WordPress site', $doc['description'] ?? null, "/wp-json [{$style}] seed {$seed} description must be the bare tagline");
                $routes = $doc['routes'] ?? [];
                self::assertNotEmpty($routes, "/wp-json [{$style}] seed {$seed} must list routes");
                foreach ($routes as $route => $meta) {
                    self::assertArrayHasKey('endpoints', $meta, "/wp-json [{$style}] seed {$seed} route {$route} must carry endpoints");
                    self::assertNotEmpty($meta['endpoints'], "/wp-json [{$style}] seed {$seed} route {$route} endpoints must be non-empty");
                    self::assertArrayHasKey('self', (array) ($meta['_links'] ?? []), "/wp-json [{$style}] seed {$seed} route {$route} must carry _links.self");
                    self::assertArrayHasKey('href', (array) ($meta['_links']['self'][0] ?? []), "/wp-json [{$style}] seed {$seed} route {$route} _links.self must carry an href");
                }
                foreach ((array) ($doc['namespaces'] ?? []) as $ns) {
                    $owned = false;
                    foreach ($routes as $meta) {
                        if (($meta['namespace'] ?? null) === $ns) {
                            $owned = true;
                            break;
                        }
                    }
                    self::assertTrue($owned, "/wp-json [{$style}] seed {$seed} namespace {$ns} must own at least one route");
                }
            }
        }
    }

    public function test_api_docs_are_stack_neutral(): void
    {
        // The OpenAPI 3.0 docs and the Swagger 2.0 doc describe one API and must not contradict each
        // other on the stack: a Java-flavoured 2.0 doc at /v2/api-docs alongside a 3.0 doc that leaks a
        // PHP docroot (/var/www/<slug>/public) would betray the fabrication. No always-on API-doc
        // surface may leak a docroot, and the two docs coexist framework-neutrally on one host.
        $inv = $this->inverter();
        foreach (['/swagger.json', '/v3/api-docs', '/openapi.yaml', '/v2/api-docs'] as $path) {
            $resp = $inv->respond(new RequestContext('GET', $path));
            self::assertNotNull($resp, "{$path} must serve a fake");
            self::assertSame(0, preg_match('#/var/www/[^\s"]*?/public#', $resp->body), "{$path} must not leak a PHP docroot: " . $resp->body);
            self::assertStringNotContainsString('springfox', $resp->body, "{$path} must not name a framework in its served body");
        }
        $v2 = $inv->respond(new RequestContext('GET', '/v2/api-docs'));
        $v3 = $inv->respond(new RequestContext('GET', '/v3/api-docs'));
        self::assertNotNull($v2);
        self::assertNotNull($v3);
        self::assertStringContainsString('"swagger": "2.0"', $v2->body, '/v2/api-docs must be a Swagger 2.0 doc');
        self::assertStringContainsString('"openapi": "3.0.3"', $v3->body, '/v3/api-docs must be an OpenAPI 3.0 doc');
    }
}
