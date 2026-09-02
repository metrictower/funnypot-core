<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler\Crs;

use RuntimeException;
use Symfony\Component\Yaml\Yaml;

/**
 * The response archetype for each CRS attack class funnypot imports.
 *
 * A honeypot has no upstream ground truth to author a response from — CRS supplies only the
 * DETECTION side — so a CRS-broadened class reuses the SAME hand-authored response funnypot
 * already serves for that class. sqli/lfi/rce read their body straight from the existing
 * template; xss uses a fixed, NON-reflecting page (reflecting attacker bytes is a deliberate,
 * human-reviewed exception in the hand-authored template — never a codegen default).
 *
 * Any `{{match.*}}` / `capture` in an archetype is stripped here, so a generated CRS template
 * can never echo attacker input by accident. An archetype body may otherwise carry
 * `{{attack.*}}` / `{{persona.*}}` directives (FP-0279): they are copied as authored text into the
 * generated CRS template and resolve per deploy at render, so the CRS twin varies exactly as its
 * hand-authored source does; `sanitize()` strips ONLY reflection directives, never these.
 *
 * `severity` is the per-class FLOOR that preserves funnypot's existing gating posture (fake
 * RCE stays `critical` = gated by default); the final template severity is the higher of this
 * floor and the CRS-mapped severity.
 * `priority` sits far below the hand-authored classes (50-90) so first-match-wins keeps the
 * specific hand rules ahead of the broad CRS alternation — CRS only widens the tail.
 */
final class CrsArchetypes
{
    private const CLASSES = [
        'sqli' => ['id' => 'attack-crs-sqli', 'from' => 'templates/attack/50-sqli.yaml', 'severity' => 'high', 'priority' => 950],
        'xss' => ['id' => 'attack-crs-xss', 'from' => null, 'severity' => 'medium', 'priority' => 951],
        'lfi' => ['id' => 'attack-crs-lfi', 'from' => 'templates/attack/31-lfi-unix.yaml', 'severity' => 'high', 'priority' => 952],
        'rce' => ['id' => 'attack-crs-rce', 'from' => 'templates/attack/41-cmdi-unix.yaml', 'severity' => 'critical', 'priority' => 953],
    ];

    /** @var string */
    private $rootDir;

    public function __construct(string $rootDir)
    {
        $this->rootDir = $rootDir;
    }

    /** @return string[] the attack classes an archetype exists for */
    public static function classes(): array
    {
        return array_keys(self::CLASSES);
    }

    public static function isKnown(string $class): bool
    {
        return isset(self::CLASSES[$class]);
    }

    /**
     * Resolve one class's archetype: id, severity floor, priority, and a sanitized response.
     *
     * @return array{id:string,severity:string,priority:int,response:array{headers:array<string,string>,body:string},expect:string[]}
     */
    public function for(string $class): array
    {
        if (!isset(self::CLASSES[$class])) {
            throw new RuntimeException("No CRS archetype for class '{$class}'.");
        }
        $spec = self::CLASSES[$class];

        [$response, $expect] = $spec['from'] === null
            ? $this->inline($class)
            : $this->fromTemplate($this->rootDir . '/' . $spec['from']);

        return [
            'id' => $spec['id'],
            'severity' => $spec['severity'],
            'priority' => $spec['priority'],
            'response' => $this->sanitize($response),
            'expect' => $expect,
        ];
    }

    /**
     * @return array{0:array{headers:array<string,string>,body:string},1:string[]}
     */
    private function fromTemplate(string $file): array
    {
        if (!is_file($file)) {
            throw new RuntimeException("Archetype template missing: {$file}");
        }
        $doc = Yaml::parseFile($file);
        if (!is_array($doc) || !isset($doc['response'])) {
            throw new RuntimeException("Archetype template has no response: {$file}");
        }
        $response = (array) $doc['response'];

        return [
            [
                'headers' => array_map('strval', (array) ($response['headers'] ?? [])),
                'body' => (string) ($response['body'] ?? ''),
            ],
            array_map('strval', (array) ($doc['expect'] ?? [])),
        ];
    }

    /**
     * Fixed, non-reflecting bodies for classes whose hand-authored template reflects input.
     *
     * @return array{0:array{headers:array<string,string>,body:string},1:string[]}
     */
    private function inline(string $class): array
    {
        if ($class === 'xss') {
            // FP-0279: the search decline page's title + copy are per-deploy seeded via
            // {{attack.page.*:search}} so the body stops being a fleet constant. There is no scanner
            // marker on this class (no expect:), so the whole page is incidental. The directives are
            // copied as authored text into 951-crs-xss.yaml and resolve per deploy at render.
            return [
                [
                    'headers' => ['Content-Type' => 'text/html; charset=utf-8'],
                    'body' => "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{{attack.page.title:search}}</title></head><body>\n"
                        . "{{attack.page.body:search}}\n"
                        . "</body></html>\n",
                ],
                [],
            ];
        }

        throw new RuntimeException("No inline archetype defined for class '{$class}'.");
    }

    /**
     * Strip any reflection directive so a generated template can never echo attacker bytes.
     *
     * @param array{headers:array<string,string>,body:string} $response
     * @return array{headers:array<string,string>,body:string}
     */
    private function sanitize(array $response): array
    {
        $strip = static function (string $s): string {
            return (string) preg_replace(
                '/\{\{\s*(?:urldecode:)?match\.[^}]*\}\}/',
                '',
                $s
            );
        };

        $response['body'] = $strip($response['body']);
        $headers = [];
        foreach ($response['headers'] as $name => $value) {
            $headers[(string) $name] = $strip((string) $value);
        }
        $response['headers'] = $headers;

        return $response;
    }
}
