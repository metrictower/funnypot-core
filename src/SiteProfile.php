<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * Position-blind input the caller supplies to classify()/synthesize() (two-phase design §2.3).
 *
 * Data, not behavior beyond one oracle:
 *  - declaredStack: what the host claims to run (e.g. ['php','nginx','wordpress']); keeps a
 *    fake coherent with the real fingerprint. Advisory in v1.
 *  - routeExists: the collision oracle. A real route on the host demotes a would-be probe to
 *    clean (classify) and makes synthesize() decline a collision, so a fake never shadows a
 *    live endpoint. null ⇒ "unknown, assume none" — the classic FALLBACK/404 honeypot, whose
 *    every path is fair game (today's behavior, reproduced by ::empty()).
 *
 * The oracle is a closure the caller passes; core never reaches into a router.
 *
 * 7.3-clean: classic constructor, docblocked untyped properties (no promotion / typed props).
 */
final class SiteProfile
{
    /** @var string[] declared host stack; advisory */
    public $declaredStack;

    /** @var callable|null fn(string $method, string $path): bool — real-route oracle; null ⇒ none */
    public $routeExists;

    /**
     * @param string[]      $declaredStack
     * @param callable|null $routeExists
     */
    public function __construct(array $declaredStack = [], ?callable $routeExists = null)
    {
        $this->declaredStack = $declaredStack;
        $this->routeExists = $routeExists;
    }

    /** No declared stack, no oracle — reproduces today's FALLBACK/404 behavior exactly. */
    public static function empty(): self
    {
        return new self([], null);
    }

    /**
     * True when the host declares a genuine route for this method+path. False whenever no
     * oracle was supplied — the safe default that never demotes a probe by accident.
     */
    public function hasRoute(string $method, string $path): bool
    {
        if ($this->routeExists === null) {
            return false;
        }

        return ($this->routeExists)($method, $path) === true;
    }
}
