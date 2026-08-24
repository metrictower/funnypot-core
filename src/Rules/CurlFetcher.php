<?php

declare(strict_types=1);

namespace Funnypot\Rules;

/**
 * Default transport: HTTPS GET via ext-curl, pinned to an allow-listed set of hosts with
 * redirects followed only while they stay on the allow-list.
 *
 * Anti-SSRF/rebind posture (T9 in the security review): the fetch URL's host must be on the
 * allow-list before the request, every redirect Location is re-checked against it, and the
 * scheme must stay HTTPS. Even so, `where the bytes came from` is not the real trust anchor —
 * the signed-digest verify in RulesUpdater is; this class just refuses the obvious footguns.
 */
final class CurlFetcher implements HttpFetcher
{
    /** @var string[] lower-case hosts this fetcher will talk to */
    private $allowedHosts;

    /** @var int */
    private $maxBytes;

    /** @var int */
    private $timeoutSeconds;

    /**
     * @param string[] $allowedHosts
     */
    public function __construct(
        array $allowedHosts = ['github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com'],
        int $maxBytes = 67108864,
        int $timeoutSeconds = 30
    ) {
        $this->allowedHosts = array_map('strtolower', $allowedHosts);
        $this->maxBytes = $maxBytes;
        $this->timeoutSeconds = $timeoutSeconds;
    }

    public function get(string $url): string
    {
        if (!function_exists('curl_init')) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_NO_TRANSPORT,
                'ext-curl is not available; cannot fetch a rules release.'
            );
        }

        $this->assertAllowed($url);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false, // we follow manually so every hop is re-checked
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => $this->timeoutSeconds,
            CURLOPT_TIMEOUT => $this->timeoutSeconds * 4,
            CURLOPT_USERAGENT => 'funnypot-rules-updater',
            CURLOPT_FAILONERROR => false,
            CURLOPT_BUFFERSIZE => 65536,
            CURLOPT_NOPROGRESS => false,
            CURLOPT_PROGRESSFUNCTION => function ($ch, $dlTotal, $dlNow) {
                // Abort a runaway download rather than buffer it all first.
                return ($dlNow > $this->maxBytes || $dlTotal > $this->maxBytes) ? 1 : 0;
            },
        ]);

        $redirects = 0;
        while (true) {
            $body = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $err = curl_error($ch);

            if ($body === false) {
                $this->closeHandle($ch);
                throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, "GET {$url} failed: {$err}");
            }

            if ($status >= 300 && $status < 400) {
                $location = (string) curl_getinfo($ch, CURLINFO_REDIRECT_URL);
                if ($location === '' || ++$redirects > 5) {
                    $this->closeHandle($ch);
                    throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, 'Too many/invalid redirects.');
                }
                $this->assertAllowed($location);
                curl_setopt($ch, CURLOPT_URL, $location);
                $url = $location;
                continue;
            }

            $this->closeHandle($ch);

            if ($status !== 200) {
                throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, "GET {$url} returned HTTP {$status}.");
            }
            if (strlen((string) $body) > $this->maxBytes) {
                throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, 'Response exceeded the size cap.');
            }

            return (string) $body;
        }
    }

    /**
     * curl_close frees the handle only on PHP 7.x; from 8.0 it is a no-op (handles are GC-freed
     * objects) and it is deprecated as of 8.5. Call it only where it still has an effect.
     *
     * @param resource|\CurlHandle $ch
     */
    private function closeHandle($ch): void
    {
        if (\PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }
    }

    private function assertAllowed(string $url): void
    {
        $parts = parse_url($url);
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https') {
            throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, "Refusing non-HTTPS URL: {$url}");
        }
        $host = strtolower((string) ($parts['host'] ?? ''));
        if (!in_array($host, $this->allowedHosts, true)) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_FETCH_FAILED,
                "Host '{$host}' is not on the rules-update allow-list."
            );
        }
    }
}
