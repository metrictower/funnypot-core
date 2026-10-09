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

    /**
     * Built bodies kept while the PHP process lives. Long-running runtimes (Swoole, RoadRunner, the
     * app's worker) reuse them; under PHP-FPM statics reset per request, so every hit rebuilds
     * (bz2 is the costly one, ~80 ms) and embedders should rate-limit these paths.
     */
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
     * @param string $siteHost the request host (sanitized here); names the restore notes when it is a
     *                         real hostname, else the persona domain is used
     * @return array{body:string,type:string,mtime:int}|null
     */
    public function build(string $ext, string $stem, int $personaSeed, string $siteHost = '', int $maxBytes = self::DEFAULT_MAX_BYTES): ?array
    {
        if (!$this->supports($ext)) {
            return null;
        }
        $chain = $this->chain();
        if ($chain === null) {
            return null;
        }
        $host = self::hostName($siteHost);

        $key = $this->dir . '|' . $ext . '|' . $stem . '|' . $personaSeed . '|' . $host;
        if (isset(self::$built[$key])) {
            $body = self::$built[$key];
        } else {
            try {
                $body = $this->wrap($ext, $stem, $chain['bytes'], $chain['claimed'], $personaSeed, $host);
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

        return ['body' => $body, 'type' => self::TYPES[$ext], 'mtime' => self::baseTime($personaSeed) + 75];
    }

    /** A real hostname (lowercase, letters/digits/dots/hyphens, not an IP), or '' when there is none. */
    public static function hostName(string $host): string
    {
        $host = strtolower(trim($host));
        $colon = strrpos($host, ':');
        if ($colon !== false && strpos($host, ']') === false) {
            $host = substr($host, 0, $colon);
        }
        if (!preg_match('/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/', $host) || strpos($host, '.') === false
            || preg_match('/^[0-9.]+$/', $host)) {
            return '';
        }

        return $host;
    }

    private static function baseTime(int $seed): int
    {
        return self::WINDOW_START + SubSeed::index($seed, self::NS, 'mtime', self::WINDOW_SECONDS);
    }

    private function wrap(string $ext, string $stem, string $chain, int $claimed, int $seed, string $host): ?string
    {
        // Every format carries per-deploy bytes and length, so no response size or hash is shared
        // across sites: the 7z gets seeded padding, the others a persona-seeded outer layer.
        $chain = self::padSevenZip($chain, $seed);
        if ($chain === null) {
            return null;
        }
        if ($ext === '7z') {
            return $chain;
        }

        $members = $this->members($stem, $chain, $claimed, $seed, $host);
        if ($ext === 'zip') {
            return DecoyArchiveWriter::zipStore($members);
        }
        $tar = DecoyArchiveWriter::ustar($members);
        if ($ext === 'tar') {
            return $tar;
        }
        if ($ext === 'tar.gz' || $ext === 'tgz' || $ext === 'gz') {
            $out = gzencode($tar, 1);

            return $out === false ? null : $out;
        }
        $out = bzcompress($tar, 1);

        return is_string($out) ? $out : null;
    }

    /**
     * Insert seeded bytes between the last packed stream and the 7z end header, then fix the start
     * header's offset and CRC. The archive stays valid (7-Zip reports no error) while its length and
     * hash differ per deploy.
     */
    private static function padSevenZip(string $chain, int $seed): ?string
    {
        if (strlen($chain) < 32 || substr($chain, 0, 6) !== "7z\xBC\xAF\x27\x1C") {
            return null;
        }
        $h = unpack('Vlo/Vhi/Vsize/Vsizehi/Vcrc', substr($chain, 12, 20));
        if ($h['hi'] !== 0 || $h['sizehi'] !== 0 || 32 + $h['lo'] + $h['size'] > strlen($chain)) {
            return null;
        }
        $len = 2048 + SubSeed::index($seed, self::NS, 'pad', 61440);
        $pad = '';
        for ($i = 0; strlen($pad) < $len; $i++) {
            $pad .= hash('sha256', $seed . '|' . self::NS . '|pad|' . $i, true);
        }
        $pad = substr($pad, 0, $len);
        $at = 32 + $h['lo'];
        $start = pack('VVVVV', $h['lo'] + $len, 0, $h['size'], 0, $h['crc']);

        return substr($chain, 0, 8) . pack('V', crc32($start)) . $start
            . substr($chain, 32, $at - 32) . $pad . substr($chain, $at);
    }

    /**
     * @return list<array{0:string,1:string,2:int}>
     */
    private function members(string $stem, string $chain, int $claimed, int $seed, string $host): array
    {
        $persona = PersonaIdentity::fromSeed($seed);
        $site = $host !== '' ? $host : (string) $persona->field('company.domain');
        $base = self::baseTime($seed);
        // ustar names cap at 100 bytes: keep folder + member well inside it.
        $inner = substr($stem, 0, 50) . '.7z';
        $dir = substr($stem, 0, 40) . '/';

        return [
            [$dir . $inner, $chain, $base],
            [$dir . 'MANIFEST.sha256', hash('sha256', $chain) . '  ' . $inner . "\n", $base + 61],
            [$dir . 'backup.log', $this->backupLog($seed, $base, $claimed, $inner), $base + 75],
            [$dir . 'contents.txt', $this->contents($seed), $base + 70],
            [$dir . 'RESTORE.txt', $this->restoreNotes($site, $inner, $claimed), $base - 86400 * 40],
            [$dir . 'wp-config.php', $this->wpConfig($persona, $seed), $base - 86400 * 3],
        ];
    }

    /** A seeded file listing of the "backed-up" tree; its length varies per deploy (about 8-90 KB). */
    private function contents(int $seed): string
    {
        $dirs = ['var/www/html/wp-content/uploads/', 'var/www/html/wp-content/plugins/', 'var/www/html/wp-content/themes/',
            'var/www/html/wp-includes/', 'home/deploy/', 'etc/nginx/sites-enabled/', 'var/backups/mysql/'];
        $leaves = ['IMG_', 'scan_', 'invoice-', 'export_', 'class-', 'style-', 'index-', 'report_'];
        $exts = ['.jpg', '.png', '.pdf', '.php', '.css', '.js', '.csv', '.sql.gz'];
        $n = 150 + SubSeed::index($seed, self::NS, 'contents', 1350);
        $out = '';
        for ($i = 0; $i < $n; $i++) {
            $d = hash('sha256', $seed . '|' . self::NS . '|contents|' . $i);
            $year = 2019 + hexdec($d[0]) % 5;
            $month = 1 + hexdec($d[1]) % 12;
            $out .= $dirs[hexdec($d[2]) % count($dirs)]
                . ($i % 3 === 0 ? sprintf('%d/%02d/', $year, $month) : '')
                . $leaves[hexdec($d[3]) % count($leaves)] . hexdec(substr($d, 4, 4))
                . $exts[hexdec($d[8]) % count($exts)] . "\n";
        }

        return $out;
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

        return gmdate('Y-m-d H:i:s', $base - 3700) . " backup[2214]: starting nightly incremental set\n" . $lines
            . gmdate('Y-m-d H:i:s', $t + 3) . " backup[2214]: done, 0 errors\n";
    }

    private function restoreNotes(string $site, string $inner, int $claimed): string
    {
        return "Restore notes - {$site}\n\n"
            . "This is an incremental set of {$claimed} parts. Each part holds the changes since the one\n"
            . "before it and contains the next part, so they must be unpacked in order.\n\n"
            . "1. Extract {$inner}.\n"
            . "2. Keep extracting the archive found inside each part, in order.\n"
            . "3. The database export and the .env are in the final set.\n\n"
            . "Some parts were re-packed with a different tool after the NAS upgrade; use a recent 7-Zip.\n";
    }

    private function wpConfig(PersonaIdentity $persona, int $seed): string
    {
        $pw = SubSeed::chars($seed, self::NS, 'db_pw', 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%', 18);
        $dbHost = SubSeed::pick(['localhost', '127.0.0.1', 'mysql', 'db', 'localhost:3306', 'mariadb'], $seed, self::NS, 'db_host');
        $salts = '';
        foreach (['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'] as $k) {
            $salts .= "define('{$k}', '"
                . SubSeed::chars($seed, self::NS, 'salt|' . $k, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^*()-_[]{}<>~+=,.;:/?|', 64)
                . "');\n";
        }

        return "<?php\n"
            . "/** Backup copy - production settings at time of backup. */\n"
            . "define('DB_NAME', '" . $persona->field('db.wpName') . "');\n"
            . "define('DB_USER', '" . $persona->field('db.user') . "');\n"
            . "define('DB_" . "PASSWORD', '" . $pw . "');\n"
            . "define('DB_HOST', '" . $dbHost . "');\n"
            . "define('DB_CHARSET', 'utf8mb4');\n"
            . "define('DB_COLLATE', '');\n\n"
            . $salts
            . "\n\$table_prefix = 'wp_';\n\n"
            . "define('WP_DEBUG', false);\n\n"
            . "if (!defined('ABSPATH')) {\n    define('ABSPATH', __DIR__ . '/');\n}\n\n"
            . "require_once ABSPATH . 'wp-settings.php';\n";
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
