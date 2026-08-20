<?php

declare(strict_types=1);

namespace Funnypot\Tests\Support;

use Funnypot\Rules\HttpFetcher;
use Funnypot\Rules\RulesUpdateException;

/**
 * A network-free HttpFetcher: serves bytes from an in-memory URL map. Test double for the
 * RulesUpdater's fetch step so the whole verify/swap flow runs without touching the network.
 */
final class ArrayFetcher implements HttpFetcher
{
    /** @var array<string,string> */
    private $map;

    /** @param array<string,string> $map url => bytes */
    public function __construct(array $map = [])
    {
        $this->map = $map;
    }

    public function put(string $url, string $bytes): void
    {
        $this->map[$url] = $bytes;
    }

    public function get(string $url): string
    {
        if (!array_key_exists($url, $this->map)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, "no such asset: {$url}");
        }

        return $this->map[$url];
    }
}
