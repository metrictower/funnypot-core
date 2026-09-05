<?php

declare(strict_types=1);

namespace Funnypot\Core\Reaction;

/**
 * A validated, bounded query-parameter reaction intent, carried as opaque metadata on a ROUTE
 * FakeHandle. Immutable value object. The only builders are QueryIntentClassifier (from a live query)
 * and tryFromArray() (rebuilding a JSON-hopped handle); both run the SAME bounds through validate(),
 * so a forged or corrupted array can never produce an out-of-contract intent — it degrades to null.
 *
 * The kind selects one of five closed reaction families; the value is the attacker's decoded
 * parameter value, and it is echoed only as encoded display text by the renderer — never a file,
 * command, URL, callable or template selector. The value is inert data on the handle.
 *
 * 7.3-clean: classic constructor, docblocked untyped properties, private ctor, final.
 */
final class ParamIntent
{
    public const KIND_FILE_READ = 'file-read';
    public const KIND_REDIRECT_NOTICE = 'redirect-notice';
    public const KIND_DEBUG_VIEW = 'debug-view';
    public const KIND_COMMAND_RESULT = 'command-result';
    public const KIND_SEARCH_RESULT = 'search-result';

    /** Max decoded value bytes for a recognized key (mirrors QueryIntentClassifier). */
    public const MAX_VALUE_BYTES = 256;

    /**
     * The canonical key set each kind accepts. A key outside its kind's set invalidates the intent,
     * so a JSON hop can never re-home a value onto a family it did not classify as.
     *
     * @var array<string,string[]>
     */
    private const KEYS = [
        self::KIND_FILE_READ => ['file', 'path', 'page'],
        self::KIND_REDIRECT_NOTICE => ['url', 'host', 'redirect', 'next', 'ref', 'route'],
        self::KIND_DEBUG_VIEW => ['debug'],
        self::KIND_COMMAND_RESULT => ['cmd'],
        self::KIND_SEARCH_RESULT => ['q', 'search', 'msg', 'note'],
    ];

    /** @var string one of the KIND_* constants */
    public $kind;

    /** @var string the canonical (lower-cased) parameter key */
    public $key;

    /** @var string the decoded parameter value */
    public $value;

    private function __construct(string $kind, string $key, string $value)
    {
        $this->kind = $kind;
        $this->key = $key;
        $this->value = $value;
    }

    /**
     * Build from parts, re-running every bound. Null (never a throw) for an unknown kind, a key
     * outside the kind's set, or an empty/oversized/control-bearing/invalid-UTF-8 value.
     */
    public static function create(string $kind, string $key, string $value): ?self
    {
        return self::validate($kind, $key, $value) ? new self($kind, $key, $value) : null;
    }

    /**
     * Rebuild from the toArray() shape. Null (never a throw) for an unknown version, a non-map or a
     * list, any extra field, missing/non-string members, or a value that fails create()'s bounds —
     * so a forged or corrupted handle degrades to the undecorated base response.
     *
     * @param array<string,mixed> $data
     */
    public static function tryFromArray(array $data): ?self
    {
        // Exactly the four keys, nothing more (an extra field, or a positional list, is rejected).
        $allowed = ['v' => true, 'kind' => true, 'key' => true, 'value' => true];
        foreach ($data as $k => $ignored) {
            if (!isset($allowed[$k])) {
                return null;
            }
        }
        if (($data['v'] ?? null) !== 1) {
            return null;
        }
        if (!isset($data['kind'], $data['key'], $data['value'])) {
            return null;
        }
        if (!is_string($data['kind']) || !is_string($data['key']) || !is_string($data['value'])) {
            return null;
        }

        return self::create($data['kind'], $data['key'], $data['value']);
    }

    /**
     * @return array{v:int,kind:string,key:string,value:string}
     */
    public function toArray(): array
    {
        return ['v' => 1, 'kind' => $this->kind, 'key' => $this->key, 'value' => $this->value];
    }

    /**
     * The canonical keys a kind accepts (used by the renderer's bucket dispatch and by validate()).
     *
     * @return string[]
     */
    public static function keysForKind(string $kind): array
    {
        return self::KEYS[$kind] ?? [];
    }

    private static function validate(string $kind, string $key, string $value): bool
    {
        if (!isset(self::KEYS[$kind])) {
            return false;
        }
        if (!in_array($key, self::KEYS[$kind], true)) {
            return false;
        }
        $len = strlen($value);
        if ($len < 1 || $len > self::MAX_VALUE_BYTES) {
            return false;
        }
        // NUL, C0 and DEL are never legal in a reaction value; a forged intent must not smuggle them
        // past the classifier's parser (they would break a header/body or read as a control tell).
        if (preg_match('/[\x00-\x1f\x7f]/', $value) === 1) {
            return false;
        }
        // C1 controls as UTF-8 code points (U+0080..U+009F => 0xC2 0x80..0xC2 0x9F).
        if (preg_match('/\xc2[\x80-\x9f]/', $value) === 1) {
            return false;
        }
        // Reject invalid UTF-8 without an mbstring dependency (the package requires only php >=7.3).
        if (preg_match('//u', $value) !== 1) {
            return false;
        }

        return true;
    }
}
