<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Template\DirectiveRenderer;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * FP-0284 — config-disclosure coherence. The ticket's #1 invariant: every config-disclosure surface
 * (/.env, wp-config.php-backup, /.aws/config, terraform.tfstate and their /@fs mirrors) renders its
 * region / DB story / brand from the ONE per-deploy PersonaIdentity, so a single deployment discloses
 * exactly one AWS region and one DB story — never the three-region incoherence that shipped before.
 *
 * The render bytes are pinned by SHAPE (regex) and by comparison against PersonaIdentity::fromSeed()
 * at runtime — never a pasted secret literal (push-protection), and never a varied brand/region literal
 * (those are exactly what this ticket removes).
 */
final class ConfigDisclosureCoherenceTest extends TestCase
{
    private const ROUTES = __DIR__ . '/../resources/compiled/funnypot-routes.php';

    private const PARAM = __DIR__ . '/../resources/compiled/funnypot-param.php';

    private const TPL = __DIR__ . '/../templates';

    /** Deploy materials swept: the two fleet defaults the gate also renders, plus a per-deploy spread. */
    private function materials(): array
    {
        $mats = ['', 'funnypot'];
        for ($i = 0; $i < 40; $i++) {
            $mats[] = 'fp-0284-' . $i;
        }

        return $mats;
    }

    /** Two render seeds (per-Host crc32), so a coherence claim holds across hosts, not just one. */
    private function renderSeeds(): array
    {
        return [crc32('a.example|s'), crc32('b.example|s')];
    }

    /** The committed route body for $id — the exact string RouteTemplateEmulator renders for it. */
    private function routeBody(string $id): string
    {
        foreach ((array) (require self::ROUTES) as $rule) {
            if (is_array($rule) && ($rule['id'] ?? null) === $id) {
                return (string) ($rule['body'] ?? '');
            }
        }
        self::fail("route '{$id}' is not present in the compiled route artifact");
    }

    /** The shipped compiled /@fs param entry (behavior: traversal-read). */
    private function fsEntry(): array
    {
        $param = require self::PARAM;

        return $param['buckets']['@fs'][0];
    }

    /** Render a route body through the render path with the deploy seed wired (as prod does). */
    private function renderRoute(string $id, int $deploySeed, int $renderSeed): string
    {
        return (new DirectiveRenderer($deploySeed))->render($this->routeBody($id), [], $renderSeed);
    }

    /** Render an /@fs loot target through the real traversal-read handler with the deploy seed wired. */
    private function renderFs(string $path, int $deploySeed, int $renderSeed): string
    {
        $emu = new TemplateAttackEmulator([], [], null, null, [], $deploySeed);
        $resp = $emu->renderRule($this->fsEntry(), ['path' => $path], $renderSeed);
        self::assertNotNull($resp, "/@fs/{$path} must render");

        return $resp->body;
    }

    /** All seven disclosure bodies for one (deploy, render) point. */
    private function allBodies(int $deploySeed, int $renderSeed): array
    {
        return [
            '/.env' => $this->renderRoute('route-dotenv', $deploySeed, $renderSeed),
            'wp-config' => $this->renderRoute('route-wp-config', $deploySeed, $renderSeed),
            '/.aws/config' => $this->renderRoute('route-aws-cli-config', $deploySeed, $renderSeed),
            'tfstate' => $this->renderRoute('route-terraform-tfstate', $deploySeed, $renderSeed),
            '/@fs/.env' => $this->renderFs('.env', $deploySeed, $renderSeed),
            '/@fs/.aws/credentials' => $this->renderFs('home/deploy/.aws/credentials', $deploySeed, $renderSeed),
            '/@fs/wp-config.php' => $this->renderFs('var/www/html/wp-config.php', $deploySeed, $renderSeed),
        ];
    }

    // --- T1: exactly ONE region per deploy, and it is the persona's --------------------------------

    public function test_t1_one_region_across_all_surfaces_equals_the_persona_region(): void
    {
        foreach ($this->materials() as $mat) {
            $deploySeed = PersonaIdentity::seedFromMaterial($mat);
            $persona = PersonaIdentity::fromSeed($deploySeed);
            $region = (string) $persona->field('cloud.aws.region');
            $code = (string) $persona->field('cloud.aws.regionCode');

            foreach ($this->renderSeeds() as $renderSeed) {
                $joined = implode("\n", $this->allBodies($deploySeed, $renderSeed));

                $hits = (int) preg_match_all('/\b(?:us|eu|ap|ca|sa)-[a-z]+-\d\b/', $joined, $m);
                self::assertGreaterThan(0, $hits, "m=[{$mat}] at least one region token must be present");
                $distinct = array_values(array_unique($m[0]));
                self::assertSame([$region], $distinct, "m=[{$mat}] exactly one region across all surfaces, equal to the persona region");

                // The ElastiCache short code inside REDIS_HOST is the derived code for that same region.
                self::assertSame(
                    1,
                    preg_match('/REDIS_HOST=cache-[0-9a-f]{12}\.0001\.([a-z]+\d)\.cache\.amazonaws\.com/', $this->allBodies($deploySeed, $renderSeed)['/.env'], $rc),
                    "m=[{$mat}] REDIS_HOST endpoint shape"
                );
                self::assertSame($code, $rc[1], "m=[{$mat}] REDIS_HOST short code is the region's derived code");
            }
        }
    }

    // --- T2: ONE DB story (incl. the binding must-fix: tfstate DB == /.env DB) ----------------------

    public function test_t2_one_db_story_and_tfstate_matches_dotenv(): void
    {
        foreach ($this->materials() as $mat) {
            $deploySeed = PersonaIdentity::seedFromMaterial($mat);
            $persona = PersonaIdentity::fromSeed($deploySeed);
            $dbName = (string) $persona->field('db.name');
            $dbUser = (string) $persona->field('db.user');
            $dbPass = (string) $persona->field('db.password');
            $wpName = (string) $persona->field('db.wpName');
            $slug = (string) $persona->field('company.slug');

            // Pool disjointness: the pgsql app db and the WP MySQL db never collide.
            self::assertNotSame($dbName, $wpName, "m=[{$mat}] db.name and db.wpName must differ");

            foreach ($this->renderSeeds() as $renderSeed) {
                $b = $this->allBodies($deploySeed, $renderSeed);

                // /.env and its /@fs mirror name the persona pgsql db.
                foreach (['/.env', '/@fs/.env'] as $key) {
                    self::assertStringContainsString('DB_DATABASE=' . $dbName, $b[$key], "m=[{$mat}] {$key} DB_DATABASE");
                    self::assertStringContainsString('DB_USERNAME=' . $dbUser, $b[$key], "m=[{$mat}] {$key} DB_USERNAME");
                    self::assertStringContainsString('DB_PASSWORD=' . $dbPass, $b[$key], "m=[{$mat}] {$key} DB_PASSWORD");
                }

                // wp-config (both tiers) names the persona WP db + the shared service-account user.
                foreach (['wp-config', '/@fs/wp-config.php'] as $key) {
                    self::assertStringContainsString("define('DB_NAME', '" . $wpName . "')", $b[$key], "m=[{$mat}] {$key} DB_NAME");
                    self::assertStringContainsString("define('DB_USER', '" . $dbUser . "')", $b[$key], "m=[{$mat}] {$key} DB_USER");
                }

                // tfstate describes the SAME DB: identifier=<slug>-prod, username=db.user.
                self::assertStringContainsString('"identifier": "' . $slug . '-prod"', $b['tfstate'], "m=[{$mat}] tfstate identifier");
                self::assertStringContainsString('"username": "' . $dbUser . '"', $b['tfstate'], "m=[{$mat}] tfstate username");

                // The binding must-fix: one DB ⇒ one host + one password across /.env and tfstate.
                self::assertSame(1, preg_match('/DB_HOST=(\S+)/', $b['/.env'], $eh), "m=[{$mat}] /.env DB_HOST");
                self::assertSame(1, preg_match('/DB_PASSWORD=(\S+)/', $b['/.env'], $ep), "m=[{$mat}] /.env DB_PASSWORD");
                self::assertSame(1, preg_match('/"address": "([^"]+)"/', $b['tfstate'], $th), "m=[{$mat}] tfstate address");
                self::assertSame(1, preg_match('/"password": "([^"]+)"/', $b['tfstate'], $tp), "m=[{$mat}] tfstate password");
                self::assertSame($eh[1], $th[1], "m=[{$mat}] tfstate host must equal /.env DB_HOST (one DB, one host)");
                self::assertSame($ep[1], $tp[1], "m=[{$mat}] tfstate password must equal /.env DB_PASSWORD (one credential story)");
                // endpoint = the same host + :5432.
                self::assertStringContainsString('"endpoint": "' . $th[1] . ':5432"', $b['tfstate'], "m=[{$mat}] tfstate endpoint = address:5432");
            }
        }
    }

    // --- T3: no demo brands anywhere; identity fields are the persona's ----------------------------

    public function test_t3_no_demo_brands_and_identity_is_the_persona(): void
    {
        $banned = ['Acme', 'Northwind', 'Contoso', 'Fabrikam', 'Initech', 'example.com', 'wp_app', 'app_production', 'persona identity', '/@fs/'];

        foreach ($this->materials() as $mat) {
            $deploySeed = PersonaIdentity::seedFromMaterial($mat);
            $persona = PersonaIdentity::fromSeed($deploySeed);
            $name = (string) $persona->field('company.name');
            $domain = (string) $persona->field('company.domain');
            $slug = (string) $persona->field('company.slug');

            foreach ($this->renderSeeds() as $renderSeed) {
                foreach ($this->allBodies($deploySeed, $renderSeed) as $label => $body) {
                    foreach ($banned as $needle) {
                        self::assertStringNotContainsStringIgnoringCase($needle, $body, "m=[{$mat}] {$label} must not disclose '{$needle}'");
                    }
                    // 'app_prod' word-bounded so it never false-hits '<slug>_prod'.
                    self::assertSame(0, preg_match('/\bapp_prod\b/', $body), "m=[{$mat}] {$label} must not disclose 'app_prod'");
                }

                $b = $this->allBodies($deploySeed, $renderSeed);
                self::assertStringContainsString('APP_NAME=' . $name, $b['/.env'], "m=[{$mat}] APP_NAME is the persona company");
                self::assertStringContainsString('APP_URL=https://' . $domain, $b['/.env'], "m=[{$mat}] APP_URL is the persona domain");
                self::assertStringContainsString('AWS_BUCKET=' . $slug . '-prod-uploads', $b['/.env'], "m=[{$mat}] AWS_BUCKET carries the persona slug");
                self::assertStringContainsString("'bucket'            => 'media." . $domain . "'", $b['wp-config'], "m=[{$mat}] wp media bucket is the persona domain");
            }
        }
    }

    // --- T4: every exploit-confirmation marker survives at every seed ------------------------------

    public function test_t4_markers_and_secret_shapes_survive(): void
    {
        // Load each template's expect: list from YAML (the same source the compiler/gate assert).
        $expect = [
            'route-dotenv' => $this->expectOf('route/20-dotenv.yaml'),
            'route-wp-config' => $this->expectOf('route/40-wp-config.yaml'),
            'route-aws-cli-config' => $this->expectOf('route/236-dotaws-config.yaml'),
            'route-terraform-tfstate' => $this->expectOf('route/231-terraform-tfstate.yaml'),
        ];
        // Sanity: the loaded lists are non-empty (a silent YAML miss would make T4 vacuous).
        foreach ($expect as $id => $markers) {
            self::assertNotEmpty($markers, "expect: list for {$id} loaded");
        }

        // Secret SHAPES (regex, never a pasted key) — AKIA id adjacent to a 40-char base64 secret.
        $envAws = '/AWS_ACCESS_KEY_ID=AKIA[A-Z2-7]{16}\nAWS_SECRET_ACCESS_KEY=[A-Za-z0-9+\/]{40}\n/';
        $wpAws = "/'access-key-id'\\s+=>\\s+'AKIA[A-Z2-7]{16}',\\n\\s+'secret-access-key'\\s+=>\\s+'[A-Za-z0-9+\\/]{40}'/";

        foreach ($this->materials() as $mat) {
            $deploySeed = PersonaIdentity::seedFromMaterial($mat);
            foreach ($this->renderSeeds() as $renderSeed) {
                $b = $this->allBodies($deploySeed, $renderSeed);
                $bodyOf = [
                    'route-dotenv' => [$b['/.env'], $b['/@fs/.env']],
                    'route-wp-config' => [$b['wp-config'], $b['/@fs/wp-config.php']],
                    'route-aws-cli-config' => [$b['/.aws/config']],
                    'route-terraform-tfstate' => [$b['tfstate']],
                ];
                foreach ($expect as $id => $markers) {
                    foreach ($bodyOf[$id] as $body) {
                        foreach ($markers as $marker) {
                            self::assertStringContainsString($marker, $body, "m=[{$mat}] {$id} marker survives");
                        }
                    }
                }

                // The /.env body-match axis + AKIA adjacency shape.
                foreach ([$b['/.env'], $b['/@fs/.env']] as $env) {
                    self::assertStringContainsString('APP_DEBUG=', $env, "m=[{$mat}] APP_DEBUG= body axis survives");
                    self::assertSame(1, preg_match($envAws, $env), "m=[{$mat}] AWS id+secret adjacency + shape survive in .env");
                }
                foreach ([$b['wp-config'], $b['/@fs/wp-config.php']] as $wp) {
                    self::assertSame(1, preg_match($wpAws, $wp), "m=[{$mat}] wp-config access-key-id/secret adjacency + shape survive");
                }
            }
        }
    }

    // --- T5: determinism, cross-deploy variance, and the null-persona fallback ---------------------

    public function test_t5_determinism_variance_and_fallback(): void
    {
        $rs = $this->renderSeeds()[0];

        // Determinism: same (deploy, render) point ⇒ byte-identical.
        $a = PersonaIdentity::seedFromMaterial('fp-0284-5');
        self::assertSame($this->allBodies($a, $rs), $this->allBodies($a, $rs), 'same seed renders byte-identical');

        // Variance: two deploys differ on the body and on the company name.
        $b = PersonaIdentity::seedFromMaterial('fp-0284-6');
        self::assertNotSame(
            $this->renderRoute('route-dotenv', $a, $rs),
            $this->renderRoute('route-dotenv', $b, $rs),
            'two deploys must render different /.env bodies'
        );
        self::assertNotSame(
            (string) PersonaIdentity::fromSeed($a)->field('company.name'),
            (string) PersonaIdentity::fromSeed($b)->field('company.name'),
            'two deploys must not collapse to one company'
        );

        // Fallback: with no deploy seed, the identity folds to the render seed — still ONE region
        // across all surfaces at one host (coherent per host, never a crash).
        $fallbackEnv = (new DirectiveRenderer())->render($this->routeBody('route-dotenv'), [], $rs);
        $fallbackTf = (new DirectiveRenderer())->render($this->routeBody('route-terraform-tfstate'), [], $rs);
        $joined = $fallbackEnv . "\n" . $fallbackTf;
        preg_match_all('/\b(?:us|eu|ap|ca|sa)-[a-z]+-\d\b/', $joined, $m);
        self::assertCount(1, array_unique($m[0]), 'null-persona fallback still discloses one region per host');
    }

    // --- T6: rendered bytes are fingerprint-clean --------------------------------------------------

    public function test_t6_rendered_bytes_carry_no_denied_fingerprint_token(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach ($this->materials() as $mat) {
            $deploySeed = PersonaIdentity::seedFromMaterial($mat);
            foreach ($this->renderSeeds() as $renderSeed) {
                foreach ($this->allBodies($deploySeed, $renderSeed) as $label => $body) {
                    self::assertSame([], $guard->scan($body), "m=[{$mat}] {$label} must be fingerprint-clean");
                }
            }
        }
    }

    /** The expect: list of a template YAML, parsed the same way the compiler/gate collect markers. */
    private function expectOf(string $relPath): array
    {
        $doc = Yaml::parseFile(self::TPL . '/' . $relPath);
        $markers = [];
        foreach ((array) ($doc['expect'] ?? []) as $marker) {
            $markers[] = (string) $marker;
        }

        return $markers;
    }
}
