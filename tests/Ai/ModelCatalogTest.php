<?php

declare(strict_types=1);

namespace Funnypot\Tests\Ai;

use Funnypot\Ai\ModelCatalog;
use Funnypot\Compiler\Crs\FingerprintGuard;
use PHPUnit\Framework\TestCase;

final class ModelCatalogTest extends TestCase
{
    public function test_tags_payload_shape(): void
    {
        $c = ModelCatalog::fromPackage();
        $tags = $c->ollamaTags();
        $this->assertArrayHasKey('models', $tags);
        $this->assertNotEmpty($tags['models']);
        $m = $tags['models'][0];
        foreach (['name', 'model', 'modified_at', 'size', 'digest', 'details'] as $k) {
            $this->assertArrayHasKey($k, $m);
        }
        foreach (['parent_model', 'format', 'family', 'families', 'parameter_size', 'quantization_level'] as $k) {
            $this->assertArrayHasKey($k, $m['details']);
        }
        $this->assertSame($m['name'], $m['model']);
        $this->assertSame('gguf', $m['details']['format']);
        $this->assertIsInt($m['size']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $m['digest']);
    }

    public function test_has_matches_ollama_name_and_openai_id(): void
    {
        $c = ModelCatalog::fromArray([[
            'name' => 'kimi-k3:1t', 'openai_id' => 'kimi-k3', 'size' => 640000000000,
            'digest' => str_repeat('a', 64), 'display_name' => 'Kimi K3', 'owned_by' => 'moonshotai',
            'family' => 'kimi', 'families' => ['kimi'], 'parameter_size' => '1T', 'quantization_level' => 'Q4_K_M', 'context_length' => 262144,
        ]]);
        $this->assertTrue($c->has('kimi-k3:1t'));
        $this->assertTrue($c->has('kimi-k3'));
        $this->assertFalse($c->has('gpt-4'));
        $this->assertNull($c->find('gpt-4'));
        $this->assertSame('Kimi K3', $c->find('kimi-k3')['display_name']);
    }

    public function test_openai_and_anthropic_envelopes(): void
    {
        $c = ModelCatalog::fromPackage();
        $o = $c->openAiModels();
        $this->assertSame('list', $o['object']);
        $this->assertSame('model', $o['data'][0]['object']);
        $a = $c->anthropicModels();
        $this->assertArrayHasKey('has_more', $a);
        $this->assertArrayHasKey('first_id', $a);
        $this->assertArrayHasKey('last_id', $a);
        $this->assertSame('model', $a['data'][0]['type']);
    }

    public function test_all_real_models_present(): void
    {
        $c = ModelCatalog::fromPackage();
        $this->assertGreaterThanOrEqual(8, count($c->all()));
    }

    public function test_ollama_show_reflects_and_missing_null(): void
    {
        $c = ModelCatalog::fromPackage();
        $first = $c->all()[0]['name'];
        $show = $c->ollamaShow($first);
        $this->assertArrayHasKey('model_info', $show);
        $this->assertArrayHasKey('details', $show);
        $this->assertNull($c->ollamaShow('does-not-exist:99b'));
    }

    public function test_ps_has_vram_and_expires(): void
    {
        $c = ModelCatalog::fromPackage();
        $ps = $c->ollamaPs();
        $this->assertArrayHasKey('models', $ps);
        $this->assertArrayHasKey('size_vram', $ps['models'][0]);
        $this->assertArrayHasKey('expires_at', $ps['models'][0]);
    }

    /**
     * Defense-in-depth beyond the CI gate (which scans the compiled artifacts): scan every
     * catalog-served body straight from the single source of truth, so a leak is caught here
     * even if the compile step were ever skipped or its output went stale.
     */
    public function test_every_catalog_payload_is_fingerprint_clean(): void
    {
        $c = ModelCatalog::fromPackage();
        $guard = FingerprintGuard::fromPackage();

        $payloads = [
            'ollamaTags' => $c->ollamaTags(),
            'ollamaPs' => $c->ollamaPs(),
            'openAiModels' => $c->openAiModels(),
            'anthropicModels' => $c->anthropicModels(),
        ];
        foreach ($payloads as $name => $payload) {
            $hits = $guard->scan((string) json_encode($payload, JSON_UNESCAPED_SLASHES));
            $this->assertSame([], $hits, "{$name}() must be fingerprint-clean");
        }

        foreach ($c->all() as $entry) {
            $name = (string) $entry['name'];
            $hits = $guard->scan((string) json_encode($c->ollamaShow($name), JSON_UNESCAPED_SLASHES));
            $this->assertSame([], $hits, "ollamaShow('{$name}') must be fingerprint-clean");
        }
    }
}
