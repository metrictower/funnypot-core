<?php

declare(strict_types=1);

namespace Funnypot\Laravel;

use Funnypot\Config;
use Funnypot\Engine;
use Funnypot\Observer;
use Funnypot\Honeypot;
use Funnypot\NullObserver;

/**
 * Laravel bridge. Auto-discovered via composer.json extra.laravel.providers.
 * This class (and the rest of src/Laravel/*) is the ONLY code in the package
 * that touches Illuminate\* — always by FQCN, never `use`-imported — so the
 * package has no hard Laravel dependency: illuminate/support/illuminate/console
 * stay composer "suggest", never "require". A non-Laravel consumer of the
 * package never loads this file (nothing autoloads it) and needs neither.
 */
final class FunnypotServiceProvider extends \Illuminate\Support\ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/funnypot.php', 'funnypot');

        $this->app->singleton(Engine::class, function ($app): Engine {
            $config = (array) $app['config']->get('funnypot', []);

            return Honeypot::default(
                self::buildConfig($config, $app),
                $app->bound(Observer::class) ? $app->make(Observer::class) : new NullObserver()
            );
        });

        $this->app->alias(Engine::class, Honeypot::class);
    }

    public function boot(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../../config/funnypot.php' => $this->publishedConfigPath(),
        ], 'funnypot-config');

        $this->commands([
            Console\UpdateTemplatesCommand::class,
        ]);
    }

    /** @return array<int,string> */
    public function provides(): array
    {
        return [Engine::class, Honeypot::class];
    }

    private function publishedConfigPath(): string
    {
        return function_exists('config_path')
            ? config_path('funnypot.php')
            : $this->app->basePath('config/funnypot.php');
    }

    /**
     * Map the published config array onto Config's constructor. Closure knobs
     * (gate, trustedBypass, killSwitch, personaSeed, probeSignature) are taken
     * verbatim from config — a plain PHP config file can return a closure value
     * like any other, so this bridge never invents policy of its own.
     *
     * @param array<string,mixed> $config
     * @param mixed                $app
     */
    private static function buildConfig(array $config, $app): Config
    {
        $seedSalt = $config['seed_salt'] ?? null;
        if (!is_string($seedSalt) || $seedSalt === '') {
            $seedSalt = (string) $app['config']->get('app.key', '');
        }

        return new Config(
            mode: (string) ($config['mode'] ?? 'detect'),
            gate: $config['gate'] ?? null,
            pathScope: (string) ($config['path_scope'] ?? 'matched-only'),
            personaSeed: $config['persona_seed'] ?? null,
            personaBreadth: (string) ($config['persona_breadth'] ?? 'coherent'),
            responseStyle: (string) ($config['response_style'] ?? \Funnypot\Response\Style::MINIMAL),
            severityCeiling: (string) ($config['severity_ceiling'] ?? 'high'),
            maxBodyBytes: (int) ($config['max_body_bytes'] ?? 65536),
            latencyMs: (int) ($config['latency_ms'] ?? 0),
            trustedBypass: $config['trusted_bypass'] ?? null,
            killSwitch: $config['kill_switch'] ?? null,
            probeSignature: $config['probe_signature'] ?? null,
            seedSalt: $seedSalt,
            exclude: (array) ($config['exclude'] ?? [])
        );
    }
}
