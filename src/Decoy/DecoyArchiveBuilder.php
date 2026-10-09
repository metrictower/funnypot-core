<?php

declare(strict_types=1);

namespace Funnypot\Core\Decoy;

use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SubSeed;

/**
 * Builds the bytes served for a backup-style archive probe from the one shipped nested chain
 * (resources/decoy/chain.7z, built offline by scripts/dev/decoy-chain/build-decoy-chain.py).
 *
 * .7z is served verbatim. Every other format wraps the chain at request time in a format PHP can
 * write here — zip and tar always, gzip/bzip2 only when ext-zlib/ext-bz2 are loaded — together with
 * a few persona-seeded files (wp-config.php, backup.log, MANIFEST.sha256, RESTORE.txt), so the outer
 * archive differs per deploy. A format this host cannot write, a missing or altered chain, or an
 * over-cap result all return null and the host serves its own 404.
 *
 * Pure apart from reading the shipped chain once per process: same (ext, stem, persona seed) gives
 * the same bytes. Every fabricated credential is inert and deliberately not the persona's own.
 */
final class DecoyArchiveBuilder
{
    public const DEFAULT_MAX_BYTES = 1310720;

    private const NS = SubSeed::NS_ARCHIVE;
    private const WINDOW_START = 1672531200; // 2023-01-01
    private const WINDOW_SECONDS = 63072000; // two years

    private const TYPES = [
        '7z' => 'application/x-7z-compressed',
        'zip' => 'application/zip',
        'tar' => 'application/x-tar',
        'tar.gz' => 'application/gzip',
        'tgz' => 'application/gzip',
        'gz' => 'application/gzip',
        'tar.bz2' => 'application/x-bzip2',
        'tbz2' => 'application/x-bzip2',
        'bz2' => 'application/x-bzip2',
    ];

    /** Built bodies kept per process, so repeat hits (and HEAD) skip re-wrapping; bz2 costs ~85 ms. */
    private const MEMO_MAX = 6;

    /** @var array<string,array{bytes:string,claimed:int}> verified chains keyed by directory */
    private static $chains = [];

    /** @var array<string,string> built bodies keyed by dir|ext|stem|seed, oldest first */
    private static $built = [];

    /** @var string */
    private $dir;

    /** @var bool */
    private $gzip;

    /** @var bool */
    private $bzip2;

    /**
     * @param string|null $dir   directory holding chain.7z + chain.json (default: the shipped resources)
     * @param bool|null   $gzip  override gzip availability (tests); null detects gzencode()
     * @param bool|null   $bzip2 override bzip2 availability (tests); null detects bzcompress()
     */
    public function __construct(?string $dir = null, ?bool $gzip = null, ?bool $bzip2 = null)
    {
        $this->dir = $dir ?? dirname(__DIR__, 2) . '/resources/decoy';
        $this->gzip = $gzip ?? function_exists('gzencode');
        $this->bzip2 = $bzip2 ?? function_exists('bzcompress');
    }

    /** True when this host can serve the canonical extension at all. */
    public function supports(string $ext): bool
    {
        if (!isset(self::TYPES[$ext])) {
            return false;
        }
        if ($ext === 'tar.gz' || $ext === 'tgz' || $ext === 'gz') {
            return $this->gzip;
        }
        if ($ext === 'tar.bz2' || $ext === 'tbz2' || $ext === 'bz2') {
            return $this->bzip2;
        }

        return true;
    }

    /**
     * @return array{body:string,type:string,filename:string}|null
     */
    public function build(string $ext, string $stem, int $personaSeed, int $maxBytes = self::DEFAULT_MAX_BYTES): ?array
    {
        if (!$this->supports($ext)) {
            return null;
        }
        $chain = $this->chain();
        if ($chain === null) {
            return null;
        }

        $key = $this->dir . '|' . $ext . '|' . $stem . '|' . $personaSeed;
        if (isset(self::$built[$key])) {
            $body = self::$built[$key];
        } else {
            try {
                $body = $this->wrap($ext, $stem, $chain['bytes'], $chain['claimed'], $personaSeed);
            } catch (\Throwable $e) {
                return null;
            }
            if (is_string($body) && $body !== '') {
                if (count(self::$built) >= self::MEMO_MAX) {
                    array_shift(self::$built);
                }
                self::$built[$key] = $body;
            }
        }
        if ($body === null || $body === '' || strlen($body) > $maxBytes) {
            return null;
        }

        return ['body' => $body, 'type' => self::TYPES[$ext], 'filename' => $stem . '.' . $ext];
    }

    private function wrap(string $ext, string $stem, string $chain, int $claimed, int $seed): ?string
    {
        if ($ext === '7z') {
            return $chain;
        }
        if ($ext === 'gz') {
            $out = gzencode($chain, 1);

            return $out === false ? null : $out;
        }
        if ($ext === 'bz2') {
            $out = bzcompress($chain, 1);

            return is_string($out) ? $out : null;
        }

        $members = $this->members($stem, $chain, $claimed, $seed);
        if ($ext === 'zip') {
            return DecoyArchiveWriter::zipStore($members);
        }
        $tar = DecoyArchiveWriter::ustar($members);
        if ($ext === 'tar') {
            return $tar;
        }
        if ($ext === 'tar.gz' || $ext === 'tgz') {
            $out = gzencode($tar, 1);

            return $out === false ? null : $out;
        }
        $out = bzcompress($tar, 1);

        return is_string($out) ? $out : null;
    }

    /**
     * @return list<array{0:string,1:string,2:int}>
     */
    private function members(string $stem, string $chain, int $claimed, int $seed): array
    {
        $persona = PersonaIdentity::fromSeed($seed);
        $domain = (string) $persona->field('company.domain');
        $base = self::WINDOW_START + SubSeed::index($seed, self::NS, 'mtime', self::WINDOW_SECONDS);
        // ustar names cap at 100 bytes: keep folder + member well inside it.
        $inner = substr($stem, 0, 50) . '.7z';
        $dir = substr($stem, 0, 40) . '/';

        return [
            [$dir . $inner, $chain, $base],
            [$dir . 'MANIFEST.sha256', hash('sha256', $chain) . '  ' . $inner . "\n", $base + 61],
            [$dir . 'backup.log', $this->backupLog($seed, $base, $claimed, $inner), $base + 75],
            [$dir . 'RESTORE.txt', $this->restoreNotes($domain, $inner, $claimed), $base - 86400 * 40],
            [$dir . 'wp-config.php', $this->wpConfig($persona, $seed), $base - 86400 * 3],
        ];
    }

    private function backupLog(int $seed, int $base, int $claimed, string $inner): string
    {
        $host = 'nas' . (1 + SubSeed::index($seed, self::NS, 'nas', 4)) . '.internal';
        $lines = '';
        $t = $base - 3600;
        $parts = [1, 2, 3, 214, 215, 216, $claimed - 2, $claimed - 1, $claimed];
        foreach ($parts as $i => $part) {
            $t += 7 + SubSeed::index($seed, self::NS, 'log' . $i, 300);
            $lines .= gmdate('Y-m-d H:i:s', $t) . " backup[2214]: part {$part}/{$claimed} verified OK\n";
        }
        $t += 12;
        $lines .= gmdate('Y-m-d H:i:s', $t) . " backup[2214]: wrote {$inner} to //{$host}/share/backups\n";

        return gmdate('Y-m-d H:i:s', $base - 3700) . " backup[2214]: starting nightly full backup\n" . $lines
            . gmdate('Y-m-d H:i:s', $t + 3) . " backup[2214]: done, 0 errors\n";
    }

    private function restoreNotes(string $domain, string $inner, int $claimed): string
    {
        return "Restore notes - {$domain}\n\n"
            . "The full backup is split into {$claimed} parts. Each part contains the next one, nested,\n"
            . "so no single file goes over the NAS share's 4 GB FAT32 limit.\n\n"
            . "1. Extract {$inner}.\n"
            . "2. Keep extracting the archive found inside each part, in order.\n"
            . "3. The database export and the .env are in the final set.\n\n"
            . "Some parts were re-packed with a different tool after the NAS upgrade; use a recent 7-Zip.\n";
    }

    private function wpConfig(PersonaIdentity $persona, int $seed): string
    {
        $pw = SubSeed::chars($seed, self::NS, 'db_pw', 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%', 18);
        $salts = '';
        foreach (['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY'] as $k) {
            $salts .= "define('{$k}', '"
                . SubSeed::chars($seed, self::NS, 'salt|' . $k, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^*()-_[]{}<>~+=,.;:/?|', 64)
                . "');\n";
        }

        return "<?php\n"
            . "/** Backup copy - production settings at time of backup. */\n"
            . "define('DB_NAME', '" . $persona->field('db.wpName') . "');\n"
            . "define('DB_USER', '" . $persona->field('db.user') . "');\n"
            . "define('DB_" . "PASSWORD', '" . $pw . "');\n"
            . "define('DB_HOST', '" . $persona->field('db.host') . "');\n"
            . "define('DB_CHARSET', 'utf8mb4');\n\n"
            . $salts
            . "\n\$table_prefix = 'wp_';\n";
    }

    /**
     * @return array{bytes:string,claimed:int}|null
     */
    private function chain(): ?array
    {
        // Only a verified chain is cached: a file missing mid-deploy is retried on the next request.
        if (!isset(self::$chains[$this->dir])) {
            $c = $this->loadChain();
            if ($c === false) {
                return null;
            }
            self::$chains[$this->dir] = $c;
        }

        return self::$chains[$this->dir];
    }

    /**
     * @return array{bytes:string,claimed:int}|false
     */
    private function loadChain()
    {
        $manifest = @file_get_contents($this->dir . '/chain.json');
        $bytes = @file_get_contents($this->dir . '/chain.7z');
        if (!is_string($manifest) || !is_string($bytes)) {
            return false;
        }
        $m = json_decode($manifest, true);
        if (!is_array($m) || !isset($m['sha256'], $m['bytes'])
            || strlen($bytes) !== (int) $m['bytes'] || !hash_equals((string) $m['sha256'], hash('sha256', $bytes))) {
            return false;
        }

        return ['bytes' => $bytes, 'claimed' => max(3, (int) ($m['claimed_parts'] ?? 1200))];
    }
}
