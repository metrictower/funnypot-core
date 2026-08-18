<?php

declare(strict_types=1);

namespace Funnypot\Template;

use Funnypot\Detection;
use Funnypot\RequestContext;
use Funnypot\SynthesizedResponse;
use Funnypot\TemplateMatch;

/**
 * Data-driven attack emulation. Interprets compiled attack rules (from funnypot templates)
 * against a request — the same job the hand-coded Attack\Signature classes did, but every
 * emulation is now data. First rule whose match conditions all hold wins; its response is
 * rendered through the bounded DirectiveRenderer and served.
 *
 * Runtime is PHP-only: rules are a frozen PHP array (compiled from YAML at build time).
 */
final class TemplateAttackEmulator
{
    private DirectiveRenderer $renderer;

    /** @var array<string,true> rule ids the operator has switched off */
    private array $disabled = [];

    /**
     * @param array<int,array<string,mixed>> $rules  compiled attack rules
     * @param array<string,string>           $canary operator tripwire tokens
     */
    public function __construct(
        private array $rules,
        private array $canary = []
    ) {
        $this->renderer = new DirectiveRenderer();
    }

    /** @param array<string,string> $canary */
    public static function fromFile(string $path, array $canary = []): self
    {
        $rules = is_file($path) ? require $path : [];

        return new self(is_array($rules) ? $rules : [], $canary);
    }

    /** Build against the attack rules compiled into the package. */
    public static function fromPackage(array $canary = []): self
    {
        return self::fromFile(dirname(__DIR__, 2) . '/resources/compiled/funnypot-attack.php', $canary);
    }

    /**
     * Restrict to the operator's enabled set — rule ids in $disabled are skipped, so a vuln
     * switched off in the emulation catalog is never served. Fluent for construction.
     *
     * @param string[] $disabledIds
     */
    public function disable(array $disabledIds): self
    {
        foreach ($disabledIds as $id) {
            $this->disabled[$id] = true;
        }

        return $this;
    }

    public function emulate(RequestContext $r, int $seed = 0): ?SynthesizedResponse
    {
        foreach ($this->rules as $rule) {
            if ($this->disabled !== [] && isset($this->disabled[(string) ($rule['id'] ?? '')])) {
                continue;
            }
            $captures = $this->match($r, $rule);
            if ($captures === null) {
                continue;
            }

            $response = $rule['response'] ?? [];
            $body = $this->renderer->render((string) ($response['body'] ?? ''), $captures, $seed, $this->canary);

            $headers = [];
            foreach ((array) ($response['headers'] ?? []) as $name => $value) {
                $headers[(string) $name] = $this->renderer->render((string) $value, $captures, $seed, $this->canary);
            }
            if ($headers === []) {
                $headers = ['Content-Type' => 'text/plain; charset=utf-8'];
            }

            // C8: a rendered header value (e.g. a reflected redirect Location) must not carry
            // CR/LF/NUL. If it does, decline this rule (no header splitting).
            foreach ($headers as $name => $value) {
                if (preg_match('/[\r\n\x00]/', (string) $name) === 1 || preg_match('/[\r\n\x00]/', $value) === 1) {
                    return null;
                }
            }

            $id = (string) ($rule['id'] ?? 'attack');
            $severity = (string) ($rule['severity'] ?? 'high');
            $detection = new Detection(
                true,
                [new TemplateMatch($id, $severity, array_map('strval', (array) ($rule['tags'] ?? [])), $id)],
                $id,
                $severity
            );

            return new SynthesizedResponse((int) ($rule['status'] ?? 200), $headers, $body, $detection);
        }

        return null;
    }

    /** Attacker-controlled surfaces are capped before regex to bound catastrophic backtracking. */
    private const MAX_SURFACE = 32768;

    /**
     * Match all of a rule's conditions (AND). Returns the capture groups used by {{match.N}} —
     * the groups of the condition marked `capture: true`, else the first regex condition's —
     * or an empty array when matched with no captures, or null when any condition fails.
     *
     * @param array<string,mixed> $rule
     * @return array<int|string,string>|null
     */
    private function match(RequestContext $r, array $rule): ?array
    {
        $captures = null;
        foreach ((array) ($rule['match'] ?? []) as $cond) {
            $surface = $this->surface($r, (string) ($cond['in'] ?? 'request'));
            if (strlen($surface) > self::MAX_SURFACE) {
                $surface = substr($surface, 0, self::MAX_SURFACE);
            }
            $ci = ($cond['ci'] ?? true) !== false;

            if (isset($cond['regex'])) {
                $flags = ($ci ? 'i' : '') . (($cond['dotall'] ?? false) ? 's' : '');
                $result = preg_match('~' . $cond['regex'] . '~' . $flags, $surface, $m);
                // A PCRE error (false / backtrack limit) is a bad authored pattern, not a hit:
                // fail the whole rule so a broken template can never emulate.
                if ($result !== 1 || preg_last_error() !== PREG_NO_ERROR) {
                    return null;
                }
                if ($captures === null || ($cond['capture'] ?? false) === true) {
                    $captures = $m;
                }
            } elseif (isset($cond['contains'])) {
                $needle = (string) $cond['contains'];
                $hit = $ci ? stripos($surface, $needle) : strpos($surface, $needle);
                if ($hit === false) {
                    return null;
                }
            } else {
                return null;
            }
        }

        return $captures ?? [];
    }

    private function surface(RequestContext $r, string $in): string
    {
        if (strncmp($in, 'header:', 7) === 0) {
            $name = substr($in, 7);
            foreach ($r->headers as $key => $value) {
                if (strcasecmp((string) $key, $name) === 0) {
                    return (string) $value;
                }
            }

            return '';
        }

        switch ($in) {
            case 'header':
            case 'headers':
                return implode(' ', array_map('strval', $r->headers));
            case 'path':
                return $r->path;
            case 'query':
                return $r->query;
            case 'body':
                return (string) ($r->rawBody ?? '');
            case 'request':
            default:
                $raw = $r->path . ' ' . $r->query . ' ' . (string) ($r->rawBody ?? '');

                return $raw . ' ' . rawurldecode($raw);
        }
    }
}
