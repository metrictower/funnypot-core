<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * Framework-agnostic snapshot of an incoming HTTP request.
 *
 * Primitives only — the core never parses or reflects $rawBody. Adapters
 * (PSR-15, Laravel, plain 404 handler) build this from their own request type.
 */
final class RequestContext
{
    /** @var string */
    public $method;

    /** @var string */
    public $path;

    /** @var string */
    public $query;

    /** @var array<string,string> */
    public $headers;

    /** @var string|null */
    public $rawBody;

    /** @var string */
    public $host;

    /** @var string */
    public $scheme;

    /**
     * @var string Wire HTTP version ('1.1', '2', '3', or '' when unknown). Read only by the
     * request-shape bot-signal self-consistency checks (an HTTP/2 request must not carry a
     * Connection header).
     */
    public $httpVersion;

    /** @param array<string,string> $headers */
    public function __construct(
        string $method,
        string $path,
        string $query = '',
        array $headers = [],
        ?string $rawBody = null,
        string $host = '',
        string $scheme = 'https',
        string $httpVersion = ''
    ) {
        $this->method = $method;
        $this->path = $path;
        $this->query = $query;
        $this->headers = $headers;
        $this->rawBody = $rawBody;
        $this->host = $host;
        $this->scheme = $scheme;
        $this->httpVersion = $httpVersion;
    }

    /**
     * Best-effort build from PHP superglobals, for the plain 404-handler path.
     */
    public static function fromGlobals(): self
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $target = $_SERVER['REQUEST_URI'] ?? '/';

        $path = $target;
        $query = '';
        $qpos = strpos($target, '?');
        if ($qpos !== false) {
            $path = substr($target, 0, $qpos);
            $query = substr($target, $qpos + 1);
        }

        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (strncmp($key, 'HTTP_', 5) === 0) {
                $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                $headers[$name] = (string) $value;
            }
        }

        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';

        // Capture the body for write methods (capped) so the app can log the exploit
        // payload an attacker POSTs. The core never parses or reflects it.
        $rawBody = null;
        if (in_array(strtoupper((string) $method), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $raw = @file_get_contents('php://input', false, null, 0, 65536);
            $rawBody = $raw === false || $raw === '' ? null : $raw;
        }

        // SERVER_PROTOCOL is like 'HTTP/1.1' or 'HTTP/2.0'; keep just the version token.
        $protocol = (string) ($_SERVER['SERVER_PROTOCOL'] ?? '');
        $httpVersion = strncmp($protocol, 'HTTP/', 5) === 0 ? substr($protocol, 5) : '';

        return new self(
            (string) $method,
            $path,
            $query,
            $headers,
            $rawBody,
            (string) ($_SERVER['HTTP_HOST'] ?? ''),
            $scheme,
            $httpVersion
        );
    }
}
