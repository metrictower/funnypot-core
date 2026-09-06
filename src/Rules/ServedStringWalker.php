<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

/**
 * The one served-string enumerator shared by the fingerprint gate and the fetch-time rescan. It
 * walks a compiled artifact and returns EVERY served string leaf keyed by its path, so the gate
 * scans by construction instead of hand-enumerating rule shapes (the escape that let a nested
 * served field slip past the old descent-per-shape gate). A string leaf is served unless its key
 * is on the explicit skip-list below — the invariant is scan-by-default, fail-closed: a new served
 * field is scanned the moment it appears, and only a matcher/identifier field is ever pruned.
 *
 * String KEYS are scanned only in header-name positions (`headers`, `h`, `th`), where the name is
 * itself served; every other associative key is structural and never scanned.
 */
final class ServedStringWalker
{
    /**
     * Rule-family keys whose subtree is NOT served: matcher fields (match the ATTACKER's request,
     * so a nuclei-probe detector legitimately carries a scanner word here), literal prefilters,
     * param-route matcher fields, and identifiers (inert, never a served byte). `body` is added
     * per-call for a `bin` rule (its body is opaque base64 image bytes). Append-only; each entry
     * is a field matched against the request or an id, never something an attacker sees echoed.
     *
     * @var array<string,true>
     */
    private const RULE_SKIP = [
        'match' => true,               // matcher regexes/literals over attacker input
        'when' => true,                // branch-case conditions over the request
        'owns_path' => true,           // path-claim regexes
        'lit' => true,                 // literal prefilter over the request
        'lit_in' => true,              // where the prefilter looks
        'regex' => true,               // param-route matcher
        'captures' => true,            // param-route capture names
        'suffix' => true,              // param-route matcher
        'basename' => true,            // param-route matcher
        'method' => true,              // method matcher
        'template_needle' => true,     // route-rule match field (future top-level use stays skipped)
        'body_word_contains' => true,  // route-rule match field (future top-level use stays skipped)
        'id' => true,                  // identifier
        'tags' => true,                // identifiers
    ];

    /**
     * Bundle-family keys NOT served: forbidden substrings (guaranteed ABSENT from the response —
     * a template may legitimately forbid WAF block-page text), product/severity/id metadata, and
     * the detect id-list. Everything else in a bundle (`bw`/`hw`/`rx`/`th`/`h` and any future
     * string key) is served verbatim and scanned. `s`/`sz`/`sig`/`amb`/`w`/`x`/`bin` are non-string.
     *
     * @var array<string,true>
     */
    private const BUNDLE_SKIP = [
        'nf' => true,   // body forbidden (absent by construction)
        'hf' => true,   // header forbidden (absent by construction)
        'pid' => true,  // product id
        'sev' => true,  // severity
        't' => true,    // template ids
        'd' => true,    // detect id-list (sibling of the bundle list on a capped key)
    ];

    /** Associative keys whose immediate children are header NAME => value(s): scan names too. */
    private const HEADER_MAP_KEYS = ['headers' => true, 'h' => true, 'th' => true];

    /** Grounded top-level rule keys (advisory: a top-level key outside this ∪ the skip set is flagged). */
    private const KNOWN_RULE_KEYS = [
        'behavior' => true, 'branch' => true, 'decoy-session' => true, 'expr-eval' => true,
        'arith-eval' => true, 'iterate' => true, 'persona_gate' => true, 'reflect_class' => true,
        'reflects_input' => true, 'response' => true, 'severity' => true, 'ssti-render' => true,
        'status' => true, 'bin' => true, 'binary_generator' => true, 'body' => true,
        'headers' => true, 'set_cookie' => true, 'taunt' => true, 'traversal-read' => true,
        'lit_ci' => true,
    ];

    /** Grounded bundle keys (advisory, as above). */
    private const KNOWN_BUNDLE_KEYS = [
        'bw' => true, 'hw' => true, 'rx' => true, 'th' => true, 'h' => true, 's' => true,
        'sz' => true, 'sig' => true, 'amb' => true, 'w' => true, 'x' => true, 'bin' => true,
    ];

    /** @var array<string,true> skip keys actually encountered across every walk so far */
    private $usedSkips = [];

    /** @var array<string,true> top-level keys seen that are neither known-served nor skip-listed */
    private $unknownKeys = [];

    /**
     * Served string leaves of one rule-shaped array (attack/route/param), key-path => text.
     *
     * @param array<string,mixed> $rule
     * @return array<string,string>
     */
    public function ruleLeaves(array $rule, string $prefix): array
    {
        $skip = self::RULE_SKIP;
        if (!empty($rule['bin'])) {
            // A bin rule's `body` is opaque base64 image bytes (a bin rule never nests a body).
            $skip['body'] = true;
        }
        $this->trackTopLevel($rule, self::KNOWN_RULE_KEYS, $skip);
        $out = [];
        $this->walk($rule, $prefix, $skip, $out);

        return $out;
    }

    /**
     * Served string leaves of one frozen bundle (nuclei-index or flat routes-index shape).
     *
     * @param array<string,mixed> $bundle
     * @return array<string,string>
     */
    public function bundleLeaves(array $bundle, string $prefix): array
    {
        $this->trackTopLevel($bundle, self::KNOWN_BUNDLE_KEYS, self::BUNDLE_SKIP);
        $out = [];
        $this->walk($bundle, $prefix, self::BUNDLE_SKIP, $out);

        return $out;
    }

    /**
     * Served string leaves of a WHOLE compiled artifact, shape-sniffed. Four real shapes:
     *  - param  (`['buckets'=>['<seg>'=>[entry,…]]]`)               → rule leaves per flattened entry
     *  - nuclei index (`['routes'=>[key=>['b'=>[bundle,…],'d'=>…]]]`) → bundle leaves per routes[key]['b'][]
     *  - flat routes-index (`['routes'=>[key=>[bundle,…]]]`)         → bundle leaves per routes[key][]
     *  - rule list (`[rule, rule, …]`, attack/route)                → rule leaves per rule
     * Route KEYS, the index `manifest`/`templates` subtrees, and the flat-index `templates` subtree
     * are structural (the attacker's own request line / inert metadata) and are never visited.
     *
     * @param array<int|string,mixed> $artifact
     * @return array<string,string>
     */
    public function artifactLeaves(array $artifact, string $label): array
    {
        $out = [];
        if (isset($artifact['buckets']) && is_array($artifact['buckets'])) {
            foreach ($artifact['buckets'] as $seg => $entries) {
                foreach ((array) $entries as $i => $entry) {
                    if (is_array($entry)) {
                        $out += $this->ruleLeaves($entry, $label . ".buckets[{$seg}][{$i}]");
                    }
                }
            }

            return $out;
        }
        if (isset($artifact['routes']) && is_array($artifact['routes'])) {
            foreach ($artifact['routes'] as $key => $entry) {
                if (!is_array($entry)) {
                    continue;
                }
                if (isset($entry['b']) && is_array($entry['b'])) {
                    $bundles = $entry['b']; // nuclei index shape
                } elseif (isset($entry[0])) {
                    $bundles = $entry;      // flat routes-index shape
                } else {
                    continue;
                }
                foreach ($bundles as $i => $bundle) {
                    if (is_array($bundle)) {
                        $out += $this->bundleLeaves($bundle, $label . ".routes[{$key}][{$i}]");
                    }
                }
            }

            return $out;
        }
        // Flat rule list.
        foreach ($artifact as $i => $rule) {
            if (is_array($rule)) {
                $out += $this->ruleLeaves($rule, $label . "[{$i}]");
            }
        }

        return $out;
    }

    /**
     * True when rule $rule copies attacker capture bytes into served output — so the runtime egress
     * guard must NOT scan it (scanning reflected bytes would turn the guard into a two-request
     * oracle: `?q=912345` → decline, `?q=812345` → serve). Fail-safe: any rule carrying a
     * `{{…match.…}}` directive anywhere, or the `reflects_input` flag, is treated as a reflector.
     *
     * @param array<string,mixed> $rule
     */
    public static function reflectsCaptures(array $rule): bool
    {
        if (!empty($rule['reflects_input'])) {
            return true;
        }

        return self::hasMatchDirective($rule);
    }

    /**
     * Skip-list entries never encountered in any walk so far — an advisory stale-skip signal, never
     * gating (some entries are defensive future-proofing for a field only ever seen inside a pruned
     * matcher subtree).
     *
     * @return string[]
     */
    public function unusedSkips(): array
    {
        $all = self::RULE_SKIP + self::BUNDLE_SKIP;
        $out = [];
        foreach (array_keys($all) as $key) {
            if (!isset($this->usedSkips[$key])) {
                $out[] = $key;
            }
        }

        return $out;
    }

    /**
     * Top-level keys seen so far that are neither known-served nor skip-listed — an advisory nudge
     * to review the skip-list when a new shape appears. Never gating: the leaf itself is already
     * scanned by default.
     *
     * @return string[]
     */
    public function unknownKeys(): array
    {
        return array_keys($this->unknownKeys);
    }

    /**
     * @param array<int|string,mixed> $node
     * @param array<string,true> $skip
     * @param array<string,string> $out
     */
    private function walk(array $node, string $prefix, array $skip, array &$out): void
    {
        foreach ($node as $key => $value) {
            if (is_string($key)) {
                if (isset($skip[$key])) {
                    $this->usedSkips[$key] = true;
                    continue;
                }
                if (isset(self::HEADER_MAP_KEYS[$key]) && is_array($value)) {
                    $this->headerMap($value, $this->join($prefix, $key), $out);
                    continue;
                }
            }
            $path = $this->join($prefix, (string) $key);
            if (is_string($value)) {
                $out[$path] = $value;
            } elseif (is_array($value)) {
                $this->walk($value, $path, $skip, $out);
            }
        }
    }

    /**
     * Header NAME => value(s): scan the name (a served header name) and each value.
     *
     * @param array<int|string,mixed> $map
     * @param array<string,string> $out
     */
    private function headerMap(array $map, string $prefix, array &$out): void
    {
        foreach ($map as $name => $value) {
            $path = $this->join($prefix, (string) $name);
            if (is_string($name)) {
                $out[$path . '~name'] = $name;
            }
            if (is_string($value)) {
                $out[$path] = $value;
            } elseif (is_array($value)) {
                foreach ($value as $i => $sub) {
                    if (is_string($sub)) {
                        $out[$path . "[{$i}]"] = $sub;
                    } elseif (is_array($sub)) {
                        $this->walk($sub, $path . "[{$i}]", [], $out);
                    }
                }
            }
        }
    }

    private function join(string $prefix, string $key): string
    {
        return $prefix === '' ? $key : $prefix . '.' . $key;
    }

    /**
     * @param array<int|string,mixed> $node
     * @param array<string,true> $known
     * @param array<string,true> $skip
     */
    private function trackTopLevel(array $node, array $known, array $skip): void
    {
        foreach (array_keys($node) as $key) {
            if (is_string($key) && !isset($known[$key]) && !isset($skip[$key])) {
                $this->unknownKeys[$key] = true;
            }
        }
    }

    /**
     * @param array<int|string,mixed> $node
     */
    private static function hasMatchDirective(array $node): bool
    {
        foreach ($node as $value) {
            if (is_string($value)) {
                if (preg_match('/\{\{[^}]*\bmatch\.[^}]*\}\}/', $value) === 1) {
                    return true;
                }
            } elseif (is_array($value)) {
                if (self::hasMatchDirective($value)) {
                    return true;
                }
            }
        }

        return false;
    }
}
