<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Http;

use Psr\Http\Message\StreamInterface;

/**
 * Configurable in-memory PSR-7 stream stub for the PsrRequestMapper read-loop tests: it can cap
 * each read() to $maxChunk bytes (exercises the short-read loop in readBody) and can throw on
 * rewind() (exercises the fail-safe null-body path). A real Nyholm Stream reads its whole buffer in
 * one read(), so it cannot drive either edge on its own.
 */
final class StubStream implements StreamInterface
{
    /** @var string */
    private $content;

    /** @var int */
    private $pos = 0;

    /** @var int per-read byte ceiling; PHP_INT_MAX ⇒ hand back everything in one read */
    private $maxChunk;

    /** @var bool */
    private $throwOnRewind;

    /** @var bool */
    private $seekable;

    /** @var bool */
    private $readable;

    public function __construct(
        string $content,
        int $maxChunk = PHP_INT_MAX,
        bool $throwOnRewind = false,
        bool $seekable = true,
        bool $readable = true
    ) {
        $this->content = $content;
        $this->maxChunk = $maxChunk;
        $this->throwOnRewind = $throwOnRewind;
        $this->seekable = $seekable;
        $this->readable = $readable;
    }

    public function __toString(): string
    {
        return $this->content;
    }

    public function close(): void
    {
    }

    public function detach()
    {
        return null;
    }

    public function getSize(): ?int
    {
        return strlen($this->content);
    }

    public function tell(): int
    {
        return $this->pos;
    }

    public function eof(): bool
    {
        return $this->pos >= strlen($this->content);
    }

    public function isSeekable(): bool
    {
        return $this->seekable;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        $this->pos = $offset;
    }

    public function rewind(): void
    {
        if ($this->throwOnRewind) {
            throw new \RuntimeException('stream refuses to rewind');
        }
        $this->pos = 0;
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        return 0;
    }

    public function isReadable(): bool
    {
        return $this->readable;
    }

    public function read(int $length): string
    {
        $length = max(0, min($length, $this->maxChunk));
        $chunk = substr($this->content, $this->pos, $length);
        $this->pos += strlen($chunk);

        return $chunk;
    }

    public function getContents(): string
    {
        $rest = substr($this->content, $this->pos);
        $this->pos = strlen($this->content);

        return $rest;
    }

    public function getMetadata(?string $key = null)
    {
        return $key === null ? [] : null;
    }
}
