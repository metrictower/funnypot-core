<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\EmulatorCompiler;
use Funnypot\Support\PersonaIdentity;
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

    /** Invoke the compiler's private closed-vocabulary lint on a snippet. */
    private function assertKnownDirectives(string $text): void
    {
        $method = new ReflectionMethod(EmulatorCompiler::class, 'assertKnownDirectives');
        $method->setAccessible(true);
        $method->invoke(new EmulatorCompiler(), $text, 'test-fixture');
    }
}
