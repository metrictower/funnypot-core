<?php

declare(strict_types=1);

namespace Funnypot\Core\WordPress;

/**
 * Read API for the curated WordPress plugin/theme vulnerability catalog — the tier-A set the
 * `compile-wp` generator turns into versioned readme.txt / style.css decoy routes.
 *
 * This exposes ONLY the curated (tier-A) slugs. A consumer (e.g. funnypot-wordpress, FP-0395)
 * reads it for CVE tagging / telemetry, NOT to decide whether to serve: the compiled store also
 * serves ~200 generic corpus readmes (tier B), so `has()` is a curated-set membership hint, not
 * the serve gate. Serving is decided by what core's responder returns for the raw path.
 */
final class VulnCatalog
{
    /** @var array<string,array<string,mixed>> slug => entry */
    private $plugins;

    /** @var array<string,array<string,mixed>> slug => entry */
    private $themes;

    /**
     * @param array<string,array<string,mixed>> $plugins
     * @param array<string,array<string,mixed>> $themes
     */
    private function __construct(array $plugins, array $themes)
    {
        $this->plugins = $plugins;
        $this->themes = $themes;
    }

    /** Loads the real catalog shipped with the package. */
    public static function fromPackage(): self
    {
        $data = require dirname(__DIR__, 2) . '/resources/wordpress-vuln-catalog.php';

        return self::fromArray($data);
    }

    /** @param array<string,mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(
            (array) ($data['plugins'] ?? []),
            (array) ($data['themes'] ?? [])
        );
    }

    /** @return array<string,array<string,mixed>> */
    public function plugins(): array
    {
        return $this->plugins;
    }

    /** @return array<string,array<string,mixed>> */
    public function themes(): array
    {
        return $this->themes;
    }

    /** @return array<string,array<string,mixed>> every curated slug (plugins + themes). */
    public function all(): array
    {
        return $this->plugins + $this->themes;
    }

    /** True when the slug is a curated plugin OR theme (curated-set membership, not the serve gate). */
    public function has(string $slug): bool
    {
        return isset($this->plugins[$slug]) || isset($this->themes[$slug]);
    }

    /** @return array<string,mixed>|null the plugin entry, or null when the slug is not a curated plugin. */
    public function plugin(string $slug): ?array
    {
        return $this->plugins[$slug] ?? null;
    }

    /** @return array<string,mixed>|null the theme entry, or null when the slug is not a curated theme. */
    public function theme(string $slug): ?array
    {
        return $this->themes[$slug] ?? null;
    }
}
