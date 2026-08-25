<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

/**
 * The coherent fake identity: every value is a pure function of the seed, and the dependent
 * fields agree with their parents (email uses the admin username AND the company domain, the
 * db names carry the company slug). Those cross-field invariants are what keeps one synthesized
 * response from contradicting itself.
 */
final class PersonaIdentityTest extends TestCase
{
    public function test_same_seed_yields_identical_fields(): void
    {
        for ($seed = 0; $seed < 20; $seed++) {
            $a = PersonaIdentity::fromSeed($seed);
            $b = PersonaIdentity::fromSeed($seed);
            foreach (PersonaIdentity::FIELDS as $path) {
                self::assertSame($a->field($path), $b->field($path), "seed {$seed} field {$path} must be deterministic");
            }
        }
    }

    public function test_dependent_fields_are_coherent_with_their_parents(): void
    {
        for ($seed = 0; $seed < 50; $seed++) {
            $p = PersonaIdentity::fromSeed($seed);
            $slug = (string) $p->field('company.slug');
            $tld = (string) $p->field('company.tld');
            $domain = (string) $p->field('company.domain');

            self::assertSame($slug . '.' . $tld, $domain, "seed {$seed}: domain = slug.tld");
            self::assertStringEndsWith('@' . $domain, (string) $p->field('user.admin.email'), "seed {$seed}: email domain");
            self::assertStringStartsWith(
                (string) $p->field('user.admin.username') . '@',
                (string) $p->field('user.admin.email'),
                "seed {$seed}: email local part is the admin username"
            );
            self::assertStringStartsWith($slug . '_', (string) $p->field('db.name'), "seed {$seed}: db.name carries the slug");
            self::assertStringStartsWith($slug . '_', (string) $p->field('db.user'), "seed {$seed}: db.user carries the slug");
        }
    }

    public function test_credential_shapes_are_realistic(): void
    {
        for ($seed = 0; $seed < 50; $seed++) {
            $p = PersonaIdentity::fromSeed($seed);

            $ak = (string) $p->field('cloud.aws.accessKeyId');
            self::assertSame(1, preg_match('/^AKIA[A-Z2-7]{16}$/', $ak), "seed {$seed}: access key id shape");

            $hash = (string) $p->field('user.admin.passwordHash');
            self::assertSame(60, strlen($hash), "seed {$seed}: bcrypt hash is 60 chars");
            self::assertSame(1, preg_match('#^\$2y\$10\$[./A-Za-z0-9]{53}$#', $hash), "seed {$seed}: bcrypt shape + legal charset");
            // The final salt char must be a bcrypt-legal padding char (only 2 meaningful bits).
            self::assertContains($hash[28], ['.', 'O', 'e', 'u'], "seed {$seed}: 22nd salt char is a legal padding char");

            // A real AWS secret key is standard base64 — the fake must use [A-Za-z0-9+/], never '.',
            // or a secret scanner rejects it.
            $sk = (string) $p->field('cloud.aws.secretKey');
            self::assertSame(1, preg_match('#^[A-Za-z0-9+/]{40}$#', $sk), "seed {$seed}: secret key is standard base64, 40 chars");

            // Passwords are mixed-alphabet, not hex, and the two don't share a shape (length differs).
            $dbPw = (string) $p->field('db.password');
            $adminPw = (string) $p->field('user.admin.password');
            self::assertSame(20, strlen($dbPw), "seed {$seed}: db password length");
            self::assertSame(16, strlen($adminPw), "seed {$seed}: admin password length");
            self::assertSame(0, preg_match('/^[0-9a-f]+$/', $dbPw), "seed {$seed}: db password is not pure hex");
            self::assertSame(0, preg_match('/^[0-9a-f]+$/', $adminPw), "seed {$seed}: admin password is not pure hex");
        }
    }

    public function test_ai_vendor_keys_match_scanner_regexes(): void
    {
        // The counts / infix / suffix are load-bearing: a secret scanner (trufflehog/gitleaks)
        // only bites when the fake matches its regex byte-for-byte, so the shapes are asserted
        // exactly, over a range of seeds, and each must vary (not collapse to one value).
        $patterns = [
            'cloud.anthropic.apiKey' => '/^sk-ant-api03-[A-Za-z0-9_-]{93}AA$/',
            'cloud.openai.apiKey' => '/^sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}$/',
            'cloud.github.copilotToken' => '/^ghu_[0-9a-zA-Z]{36}$/',
        ];
        $spread = ['cloud.anthropic.apiKey' => [], 'cloud.openai.apiKey' => [], 'cloud.github.copilotToken' => []];

        for ($seed = 0; $seed <= 50; $seed++) {
            $p = PersonaIdentity::fromSeed($seed);
            foreach ($patterns as $field => $re) {
                $value = (string) $p->field($field);
                self::assertSame(1, preg_match($re, $value), "seed {$seed}: {$field} must match {$re} exactly");
                // Byte-identical across calls (a re-scan by the same attacker sees one stable value).
                self::assertSame(
                    $value,
                    (string) PersonaIdentity::fromSeed($seed)->field($field),
                    "seed {$seed}: {$field} must be deterministic"
                );
                $spread[$field][$value] = true;
            }
        }

        foreach ($patterns as $field => $re) {
            self::assertGreaterThan(1, count($spread[$field]), "{$field} must spread across seeds, not collapse to one value");
        }
    }

    public function test_config_disclosure_secrets_match_scanner_regexes(): void
    {
        // Config-file-disclosure secrets: same rule as the AI keys — a secret scanner only bites
        // when the shape matches byte-for-byte, so assert each regex exactly over a range of seeds,
        // require determinism, and require spread (never collapse to one value).
        $patterns = [
            'cloud.stripe.secretKey' => '/^sk_live_[0-9a-zA-Z]{24}$/',
            'cloud.sendgrid.apiKey' => '/^SG\.[0-9A-Za-z]{22}\.[0-9A-Za-z]{43}$/',
            'cloud.google.apiKey' => '/^AIza[0-9A-Za-z\-_]{35}$/',
            'secret.jwt' => '/^[0-9a-f]{64}$/',
        ];
        $spread = ['cloud.stripe.secretKey' => [], 'cloud.sendgrid.apiKey' => [], 'cloud.google.apiKey' => [], 'secret.jwt' => []];

        for ($seed = 0; $seed <= 50; $seed++) {
            $p = PersonaIdentity::fromSeed($seed);
            foreach ($patterns as $field => $re) {
                $value = (string) $p->field($field);
                self::assertSame(1, preg_match($re, $value), "seed {$seed}: {$field} must match {$re} exactly");
                self::assertSame(
                    $value,
                    (string) PersonaIdentity::fromSeed($seed)->field($field),
                    "seed {$seed}: {$field} must be deterministic"
                );
                $spread[$field][$value] = true;
            }
        }

        foreach ($patterns as $field => $re) {
            self::assertGreaterThan(1, count($spread[$field]), "{$field} must spread across seeds, not collapse to one value");
        }
    }

    public function test_no_rendered_secret_emits_the_gates_denied_digit_run(): void
    {
        // The fingerprint gate rejects a bare 6-digit token starting with 9 (\b9\d{5}\b). A rendered
        // persona secret that trips it would be classified as canned, so the boundary-prone
        // generators (base64/base64url keys, mixed-alphabet passwords) re-derive until clean.
        $guard = FingerprintGuard::fromPackage();

        // Seeds that produced the token at the commit this fix lands on — pinned so a regression is
        // caught by name: google apiKey, aws secretKey, anthropic apiKey respectively.
        foreach ([8776752, 18058005, 15473467] as $seed) {
            $p = PersonaIdentity::fromSeed($seed);
            foreach (PersonaIdentity::FIELDS as $field) {
                self::assertSame([], $guard->scan((string) $p->field($field)), "pinned seed {$seed} field {$field} must not carry a denied token");
            }
        }

        // And nothing across a wide sweep may emit it.
        for ($seed = 0; $seed <= 3000; $seed++) {
            $p = PersonaIdentity::fromSeed($seed);
            foreach (PersonaIdentity::FIELDS as $field) {
                $value = (string) $p->field($field);
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $value), "seed {$seed} field {$field} emits the denied digit run: {$value}");
            }
        }
    }

    public function test_region_is_from_the_known_set(): void
    {
        $regions = [];
        for ($seed = 0; $seed < 50; $seed++) {
            $regions[(string) PersonaIdentity::fromSeed($seed)->field('cloud.aws.region')] = true;
        }
        foreach (array_keys($regions) as $region) {
            self::assertSame(1, preg_match('/^[a-z]{2}-[a-z]+-\d$/', $region), "region '{$region}' looks like an AWS region");
        }
    }

    public function test_personas_spread_across_seeds(): void
    {
        $names = [];
        for ($seed = 0; $seed < 30; $seed++) {
            $names[(string) PersonaIdentity::fromSeed($seed)->field('company.name')] = true;
        }
        self::assertGreaterThanOrEqual(2, count($names), 'distinct seeds should not all collapse to one company');
    }

    public function test_company_names_are_not_famous_placeholders(): void
    {
        // Famous-fiction / real-domain names read as a demo (or point at innocent third parties);
        // the dictionary must be coined blends instead. Check the whole dictionary, not just a sample.
        $blocked = [
            'Acme', 'Contoso', 'Initech', 'Hooli', 'Umbrella', 'Nakatomi', 'Fabrikam', 'Globex',
            'Vandelay', 'Soylent', 'Cyberdyne', 'Tyrell', 'Aperture', 'Vertex', 'Apex',
        ];
        for ($seed = 0; $seed < 200; $seed++) {
            $name = (string) PersonaIdentity::fromSeed($seed)->field('company.name');
            self::assertNotContains($name, $blocked, "seed {$seed}: '{$name}' is a famous placeholder");
        }
    }

    public function test_unknown_field_returns_null(): void
    {
        $p = PersonaIdentity::fromSeed(7);
        self::assertNull($p->field('company.bogus'));
        self::assertNull($p->field(''));
        // Every declared FIELDS key resolves to a non-null value.
        foreach (PersonaIdentity::FIELDS as $path) {
            self::assertNotNull($p->field($path), "declared field '{$path}' must resolve");
        }
    }

    public function test_persona_value_never_collides_with_fake_name(): void
    {
        // Same seed and the same logical name ('db_pw'), but the persona `|persona|` tag and the
        // renderer's `fake.NAME` `|fake|` tag derive independent digests — so the two never coincide.
        for ($seed = 1; $seed < 25; $seed++) {
            $personaPw = (string) PersonaIdentity::fromSeed($seed)->field('db.password');
            $fakePw = substr(hash('sha256', $seed . '|fake|db_pw'), 0, 24);
            self::assertNotSame($fakePw, $personaPw, "seed {$seed}: persona value must not equal the fake.NAME value");
        }
    }

    // --- seedFromMaterial: canonical per-deploy seed, shared by the app and the template tier ---

    public function test_seed_from_material_is_deterministic(): void
    {
        self::assertSame(PersonaIdentity::seedFromMaterial('x'), PersonaIdentity::seedFromMaterial('x'));
        self::assertNotSame(PersonaIdentity::seedFromMaterial('x'), PersonaIdentity::seedFromMaterial('y'));
    }

    public function test_seed_from_material_matches_the_exact_formula(): void
    {
        foreach (['x', 'acme', 'a-per-deploy-secret', ''] as $src) {
            $expected = (int) hexdec(substr(hash('sha256', 'funnypot-persona|' . $src), 0, 15));
            self::assertSame($expected, PersonaIdentity::seedFromMaterial($src), "material '{$src}'");
        }
    }

    public function test_seed_from_material_is_a_non_negative_60_bit_int(): void
    {
        foreach (['x', 'y', 'acme', 'another-secret', ''] as $src) {
            $seed = PersonaIdentity::seedFromMaterial($src);
            self::assertGreaterThanOrEqual(0, $seed, "material '{$src}'");
            self::assertLessThan(2 ** 60, $seed, "material '{$src}'");
        }
    }

    public function test_seed_from_material_feeds_from_seed_deterministically(): void
    {
        $seed = PersonaIdentity::seedFromMaterial('acme');
        $a = PersonaIdentity::fromSeed($seed);
        $b = PersonaIdentity::fromSeed($seed);
        self::assertSame($a->field('company.name'), $b->field('company.name'));
    }

    // --- §4: the compile-time closed-field lint ---

    public function test_compiler_accepts_a_valid_persona_field(): void
    {
        $this->assertKnownDirectives('{{persona.user.admin.email}} {{persona.company.domain}}');
        $this->addToAssertionCount(1); // no exception thrown == pass
    }

    public function test_compiler_rejects_a_mistyped_persona_field(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('unknown persona field');
        $this->assertKnownDirectives('{{persona.compny.domain}}');
    }

    public function test_compiler_accepts_a_valid_fake_person_directive(): void
    {
        $this->assertKnownDirectives('{{fake.person.full:r0}} {{fake.person.username:r0}} {{fake.person.email:r0}}');
        $this->addToAssertionCount(1); // no exception thrown == pass
    }

    public function test_compiler_rejects_a_mistyped_fake_person_field(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('unknown fake.person field');
        $this->assertKnownDirectives('{{fake.person.fulll:r0}}');
    }

    /** Invoke the compiler's private closed-vocabulary lint on a snippet. */
    private function assertKnownDirectives(string $text): void
    {
        $method = new ReflectionMethod(EmulatorCompiler::class, 'assertKnownDirectives');
        $method->setAccessible(true);
        $method->invoke(new EmulatorCompiler(), $text, 'test-fixture');
    }
}
