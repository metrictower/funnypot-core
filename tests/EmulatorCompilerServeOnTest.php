<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\EmulatorCompiler;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/** `serve_on` is accepted only as `payload`, and only on a rule that can see the query or body. */
final class EmulatorCompilerServeOnTest extends TestCase
{
    /** @return array<int,array<string,mixed>> compiled rules */
    private function compile(string $in, string $serveOn = 'payload'): array
    {
        $dir = sys_get_temp_dir() . '/fp-serve-on-' . bin2hex(random_bytes(4));
        mkdir($dir);
        file_put_contents($dir . '/10-probe.yaml', <<<YAML
id: attack-serve-on-probe
severity: medium
priority: 10
tags: [attack]
match:
  - in: {$in}
    regex: 'probe-[a-z]+'
response:
  headers:
    Content-Type: 'text/plain; charset=utf-8'
  body: "nothing here\\n"
serve_on: {$serveOn}
YAML
        );
        try {
            return (new EmulatorCompiler())->compile($dir);
        } finally {
            unlink($dir . '/10-probe.yaml');
            rmdir($dir);
        }
    }

    public function test_payload_is_carried_on_a_rule_that_sees_the_query(): void
    {
        $rules = $this->compile('query');

        self::assertSame('payload', $rules[0]['serve_on'] ?? null);
    }

    public function test_a_path_only_rule_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('needs a query, body or request condition');
        $this->compile('path');
    }

    public function test_any_other_value_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("serve_on must be 'payload'");
        $this->compile('query', 'always');
    }
}
