<?php

declare(strict_types=1);

namespace Funnypot\Core\Decoy;

/**
 * Decides whether a request path names a backup-style archive the decoy chain can answer, and in
 * which format. Pure: path in, [extension, stem] out.
 *
 * By default only backup-sounding basenames match (backup22.zip, www.example.com.tar.gz,
 * site_old.tgz), so an ordinary missing asset such as /assets/app.zip still gets the host 404.
 * $anyName widens that to every basename with a servable extension.
 *
 * A bare .gz/.bz2 whose stem ends in a data extension (dump.sql.gz, users.csv.bz2) never matches:
 * that file should decompress to the data its name promises, not to an archive.
 *
 * 7.3-clean: no str_ends_with, no match.
 */
final class DecoyArchiveName
{
    /** Canonical served extensions, longest first so .tar.gz wins over .gz. */
    public const EXTENSIONS = ['tar.gz', 'tar.bz2', 'tgz', 'tbz2', 'tar', 'zip', '7z', 'gz', 'bz2'];

    private const STEMS = [
        'backup', 'backups', 'bak', 'site', 'website', 'www', 'wwwroot', 'htdocs', 'public_html', 'html',
        'web', 'upload', 'uploads', 'db', 'database', 'dump', 'sql', 'data', 'files', 'old', 'archive',
        'home', 'src', 'app', 'wordpress', 'wp', 'wp-content',
    ];

    // Atomic alternatives + possessive repeat: a long digit run is consumed one way only, so a
    // crafted name like backup<300 digits>x.zip fails in linear time instead of backtracking.
    private const SUFFIX = '(?:[._-]?(?>\d{4}[-_]?\d{2}[-_]?\d{2}|\d+|old|new|bak|backup|full|final|latest|copy|prod|live|site|www|db|files))*+';

    private const DATA_EXTENSIONS = ['sql', 'csv', 'txt', 'log', 'json', 'xml', 'tsv', 'dat', 'sqlite', 'db'];

    private const STEM_MAX = 100;

    /**
     * @return array{0:string,1:string}|null [canonical extension, sanitized stem], or null when the
     *         path is not a servable backup-style archive name.
     */
    public static function match(string $path, bool $anyName = false, string $personaDomain = ''): ?array
    {
        $slash = strrpos($path, '/');
        $base = strtolower($slash === false ? $path : substr($path, $slash + 1));
        if ($base === '' || strlen($base) > 255) {
            return null;
        }

        $ext = null;
        foreach (self::EXTENSIONS as $candidate) {
            $tail = '.' . $candidate;
            if (strlen($base) > strlen($tail) && substr($base, -strlen($tail)) === $tail) {
                $ext = $candidate;
                break;
            }
        }
        if ($ext === null) {
            return null;
        }

        $stem = substr($base, 0, -strlen($ext) - 1);
        if (($ext === 'gz' || $ext === 'bz2') && self::endsInDataExtension($stem)) {
            return null;
        }
        if (!$anyName && !preg_match(self::stemPattern($personaDomain), $stem)) {
            return null;
        }

        $clean = (string) preg_replace('/[^a-z0-9._-]/', '_', $stem);
        $clean = substr(ltrim($clean, '.-'), 0, self::STEM_MAX);

        return [$ext, $clean === '' ? 'backup' : $clean];
    }

    private static function endsInDataExtension(string $stem): bool
    {
        $dot = strrpos($stem, '.');

        return $dot !== false && in_array(substr($stem, $dot + 1), self::DATA_EXTENSIONS, true);
    }

    private static function stemPattern(string $personaDomain): string
    {
        $stems = self::STEMS;
        $domain = strtolower(trim($personaDomain));
        if ($domain !== '' && preg_match('/^[a-z0-9.-]{1,253}$/', $domain)) {
            $stems[] = $domain;
            $stems[] = 'www.' . $domain;
            $dot = strpos($domain, '.');
            if ($dot !== false && $dot > 0) {
                $stems[] = substr($domain, 0, $dot);
            }
        }
        // Longest first so a domain stem is not shadowed by a shorter generic one.
        usort($stems, static function (string $a, string $b): int {
            return strlen($b) - strlen($a);
        });
        $alternation = implode('|', array_map(static function (string $s): string {
            return preg_quote($s, '/');
        }, $stems));

        return '/^(?:' . $alternation . ')' . self::SUFFIX . '$/';
    }
}
