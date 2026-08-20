<?php

declare(strict_types=1);

namespace Funnypot\Tests\Rules;

use Funnypot\Rules\RulesLocator;
use PHPUnit\Framework\TestCase;

/**
 * The fail-safe resolver. The load-bearing property: a host that never configures a data
 * dir gets the bundled artifact, unchanged, and a broken/partial data dir self-heals to
 * that same floor rather than erroring or serving nothing.
 */
final class RulesLocatorTest extends TestCase
{
    /** @var string */
    private $tmp;

    protected function setUp(): void
    {
        RulesLocator::reset();
        putenv('FUNNYPOT_RULES_DIR');
        $this->tmp = sys_get_temp_dir() . '/funnypot-locator-' . bin2hex(random_bytes(6));
        mkdir($this->tmp . '/current', 0755, true);
    }

    protected function tearDown(): void
    {
        RulesLocator::reset();
        putenv('FUNNYPOT_RULES_DIR');
        $this->rmrf($this->tmp);
    }

    private function packaged(string $artifact): string
    {
        return dirname(__DIR__, 2) . '/resources/compiled/' . $artifact;
    }

    public function test_no_data_dir_resolves_to_the_bundled_floor(): void
    {
        self::assertSame(
            $this->packaged('nuclei-index.full.php'),
            RulesLocator::resolve('nuclei-index.full.php')
        );
    }

    public function test_data_dir_without_current_file_falls_back_to_bundled(): void
    {
        RulesLocator::useDataDir($this->tmp);

        // current/ exists but holds no artifact of this name → floor.
        self::assertSame(
            $this->packaged('funnypot-attack.php'),
            RulesLocator::resolve('funnypot-attack.php')
        );
    }

    public function test_present_current_artifact_is_preferred(): void
    {
        $path = $this->tmp . '/current/nuclei-index.full.php';
        file_put_contents($path, "<?php return ['schema' => 1];");
        RulesLocator::useDataDir($this->tmp);

        self::assertSame($path, RulesLocator::resolve('nuclei-index.full.php'));
    }

    public function test_dangling_current_symlink_self_heals_to_bundled(): void
    {
        RulesLocator::useDataDir($this->tmp);

        // A symlink swap interrupted mid-flight leaves `current` pointing at nothing.
        $releases = $this->tmp . '/releases/vGONE';
        mkdir($releases, 0755, true);
        $target = $releases . '/funnypot-routes.php';
        file_put_contents($target, "<?php return [];");
        rmdir($this->tmp . '/current');
        symlink($releases, $this->tmp . '/current');
        // resolve() returns the stable `current/…` path (opcache-friendly), not the realpath.
        self::assertSame(
            $this->tmp . '/current/funnypot-routes.php',
            RulesLocator::resolve('funnypot-routes.php')
        );

        // Now destroy the release the symlink points at: is_file() on the dangling link
        // is false, so resolution returns the bundled floor with no error path.
        unlink($target);
        $this->rmrf($releases);
        self::assertSame(
            $this->packaged('funnypot-routes.php'),
            RulesLocator::resolve('funnypot-routes.php')
        );
    }

    public function test_artifact_argument_is_reduced_to_a_leaf_name(): void
    {
        RulesLocator::useDataDir($this->tmp);

        // A traversal attempt cannot escape current/ — it is basename()'d first.
        self::assertSame(
            $this->packaged('passwd'),
            RulesLocator::resolve('../../../../etc/passwd')
        );
    }

    public function test_explicit_null_override_beats_env(): void
    {
        putenv('FUNNYPOT_RULES_DIR=' . $this->tmp);
        file_put_contents($this->tmp . '/current/funnypot-attack.php', "<?php return [];");

        // Env would prefer the data dir...
        self::assertSame(
            $this->tmp . '/current/funnypot-attack.php',
            RulesLocator::resolve('funnypot-attack.php')
        );

        // ...but an explicit null override forces the bundled floor.
        RulesLocator::useDataDir(null);
        self::assertSame(
            $this->packaged('funnypot-attack.php'),
            RulesLocator::resolve('funnypot-attack.php')
        );

        // reset() drops the override so env is consulted again.
        RulesLocator::reset();
        self::assertSame(
            $this->tmp . '/current/funnypot-attack.php',
            RulesLocator::resolve('funnypot-attack.php')
        );
    }

    private function rmrf(string $dir): void
    {
        if (!is_dir($dir)) {
            @unlink($dir);

            return;
        }
        $items = scandir($dir) ?: [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_link($path)) {
                @unlink($path);
            } elseif (is_dir($path)) {
                $this->rmrf($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }
}
