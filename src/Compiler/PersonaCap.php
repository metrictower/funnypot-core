<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * Persona cap for mega-collision route keys (SPEC §5, docs/PERSONA-CAP.md).
 *
 * A handful of keys (`GET /`, `/index.php`, `/login`) partition into hundreds/thousands
 * of single-identity bundles. Serving that many personas makes one host look "vulnerable
 * to everything" — an aggregate-scan tell. This pass, applied ONLY where a key has more
 * than {@see N} bundles, ranks the bundles by a believability score and keeps the top N,
 * so a scanner walks away with ONE coherent, plausible host.
 *
 * Detect coverage is untouched: the caller keeps the full template id-list on the entry
 * (`'d'`); only the served ('respond') set is capped.
 *
 * Compile-time only — no runtime cost.
 */
final class PersonaCap
{
    /** Cap threshold: apply only where a key has more than this many bundles. */
    public const N = 40;

    /**
     * Statuses a root/collision key may plausibly answer with. Anything else
     * (`101`/`202`/`203`/`307`/`400`/`404`/`501`) is an implausible-as-a-root identity
     * and is dropped from the served set (§5). `401`/`403`/`500` stay: there the error
     * status IS the vuln signature (auth challenge, debug page, stack trace).
     */
    private const SERVED_STATUS = [200 => true, 301 => true, 302 => true, 401 => true, 403 => true, 500 => true];

    /** Prominence tiers (§2). Slugs match compiled `pid` values verbatim. */
    private const CORE = [
        'nginx' => true, 'apache' => true, 'apache-tomcat' => true, 'php' => true,
        'iis' => true, 'openssh' => true, 'wordpress' => true, 'exchange' => true,
    ];
    private const COMMON = [
        'drupal' => true, 'joomla' => true, 'jenkins' => true, 'gitlab' => true,
        'grafana' => true, 'kibana' => true, 'springboot' => true, 'kubernetes' => true,
        'jira' => true, 'confluence' => true, 'phpmyadmin' => true, 'tomcat' => true,
        'citrix' => true, 'fortinet' => true, 'vmware' => true, 'redis' => true,
        'mongodb' => true, 'elastic' => true, 'rails' => true, 'django' => true,
        'struts' => true, 'node' => true,
    ];
    /** Grab-bag pids that name a category, not an identity — demoted, never prominent. */
    private const META = ['miscellaneous' => true, 'http-server' => true, 'discovery' => true, 'dashboard' => true];

    /** Popularity-tier weights for runtime selection (§4), DECOUPLED from keepScore. */
    private const W_CORE = 100;
    private const W_COMMON = 30;
    private const W_KNOWN = 8;
    private const W_TAIL = 2;

    /** Severity band for the score (info/unknown 0 .. critical 4). */
    private const SEV_BAND = ['info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];

    /**
     * Cap a key's bundles: drop implausible-root identities, rank the rest, keep top N.
     *
     * @param Bundle[]                                              $bundles
     * @param array<string,array{sev:string,tags:string[],name:string}> $templatesMeta
     * @return array{kept:Bundle[],dropped:Bundle[],implausible:Bundle[]}
     */
    public function cap(array $bundles, array $templatesMeta): array
    {
        // 1. Drop implausible-as-a-root-identity bundles from the served set (§5).
        $survivors = [];
        $implausible = [];
        foreach ($bundles as $b) {
            if (isset(self::SERVED_STATUS[$b->status ?? 200])) {
                $survivors[] = $b;
            } else {
                $implausible[] = $b;
            }
        }

        // 2. Rank survivors by keepScore desc; total order via a template-id tie-break so
        //    the frozen output is reproducible regardless of sort stability.
        usort($survivors, function (Bundle $x, Bundle $y) use ($templatesMeta): int {
            $sx = $this->keepScore($x, $templatesMeta);
            $sy = $this->keepScore($y, $templatesMeta);
            if ($sx !== $sy) {
                return $sy <=> $sx; // desc
            }

            return strcmp($this->tieKey($x), $this->tieKey($y));
        });

        $kept = array_slice($survivors, 0, self::N);
        $droppedByRank = array_slice($survivors, self::N);

        return [
            'kept' => $kept,
            'dropped' => array_merge($implausible, $droppedByRank),
            'implausible' => $implausible,
        ];
    }

    /**
     * Believability score (§2). Higher = a more plausible single host identity.
     *
     * @param array<string,array{sev:string,tags:string[],name:string}> $templatesMeta
     */
    public function keepScore(Bundle $b, array $templatesMeta): int
    {
        return $this->identity($b, $templatesMeta)
            + $this->realism($b, $templatesMeta)
            + 60 * min(count($b->templateIds), 12)
            + 40 * $this->sevBand($b->severity)
            + (($b->regexWitness === [] && $b->size === null) ? 25 : 0)
            + 5 * min($this->distinctTags($b, $templatesMeta), 8)
            + (($b->wholeBodyExclusive || $this->exactSize($b)) ? -15 : 0);
    }

    /**
     * Runtime selection weight (§4) from a coarse popularity tier. Independent of
     * keepScore so the *distribution* of served personas is least-anomalous.
     *
     * @param array<string,array{sev:string,tags:string[],name:string}> $templatesMeta
     */
    public function weight(Bundle $b, array $templatesMeta): int
    {
        $pid = $b->product;
        if ($pid !== '' && isset(self::CORE[$pid])) {
            return self::W_CORE;
        }
        if ($pid !== '' && isset(self::COMMON[$pid])) {
            return self::W_COMMON;
        }
        if ($pid !== '' && !isset(self::META[$pid]) && $this->hasCveVulnTag($b, $templatesMeta)) {
            return self::W_KNOWN;
        }

        return self::W_TAIL;
    }

    /**
     * @param array<string,array{sev:string,tags:string[],name:string}> $templatesMeta
     */
    private function identity(Bundle $b, array $templatesMeta): int
    {
        $pid = $b->product;
        if ($pid === '') {
            return 10;
        }
        if (isset(self::META[$pid])) {
            return -200;
        }
        if (isset(self::CORE[$pid])) {
            return 800;
        }
        if (isset(self::COMMON[$pid])) {
            return 300;
        }
        if ($this->hasCveVulnTag($b, $templatesMeta)) {
            return 80; // named product carrying a real vuln
        }

        return 10; // obscure info fingerprint
    }

    /**
     * @param array<string,array{sev:string,tags:string[],name:string}> $templatesMeta
     */
    private function realism(Bundle $b, array $templatesMeta): int
    {
        $s = $b->status ?? 200;
        if ($s === 200) {
            return 1000;
        }
        if ($s === 301 || $s === 302) {
            return 300;
        }
        if (($s === 401 || $s === 403 || $s === 500) && $this->hasErrorAuthSignature($b, $templatesMeta)) {
            return 120; // the error status IS the vuln signature
        }

        return -5000; // implausible root identity => sorts out
    }

    private function sevBand(string $sev): int
    {
        return self::SEV_BAND[strtolower($sev)] ?? 0;
    }

    private function exactSize(Bundle $b): bool
    {
        return $b->size !== null && ($b->size['op'] ?? '') === 'eq';
    }

    /**
     * @param array<string,array{sev:string,tags:string[],name:string}> $templatesMeta
     */
    private function distinctTags(Bundle $b, array $templatesMeta): int
    {
        $seen = [];
        foreach ($b->templateIds as $id) {
            foreach ($templatesMeta[$id]['tags'] ?? [] as $tag) {
                $seen[$tag] = true;
            }
        }

        return count($seen);
    }

    /**
     * @param array<string,array{sev:string,tags:string[],name:string}> $templatesMeta
     */
    private function hasCveVulnTag(Bundle $b, array $templatesMeta): bool
    {
        foreach ($b->templateIds as $id) {
            foreach ($templatesMeta[$id]['tags'] ?? [] as $tag) {
                $t = strtolower((string) $tag);
                if (strpos($t, 'cve') !== false || strpos($t, 'vuln') !== false || $t === 'kev') {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * True when an error-status bundle carries a debug/error/auth/vuln signal — i.e. the
     * status is a legitimate signature rather than a contradiction.
     *
     * @param array<string,array{sev:string,tags:string[],name:string}> $templatesMeta
     */
    private function hasErrorAuthSignature(Bundle $b, array $templatesMeta): bool
    {
        static $signal = [
            'debug' => true, 'error' => true, 'errors' => true, 'exception' => true,
            'exceptions' => true, 'stacktrace' => true, 'stacktraces' => true,
            'logs' => true, 'log' => true, 'auth' => true, 'auth-bypass' => true,
            'unauth' => true, 'unauthenticated' => true, 'authenticated' => true,
            'panel' => true, 'login' => true, 'default-login' => true,
        ];
        foreach ($b->templateIds as $id) {
            foreach ($templatesMeta[$id]['tags'] ?? [] as $tag) {
                if (isset($signal[strtolower((string) $tag)])) {
                    return true;
                }
            }
        }

        return $b->product !== '' && $this->hasCveVulnTag($b, $templatesMeta);
    }

    /** Deterministic tie-break key: the bundle's lowest template id. */
    private function tieKey(Bundle $b): string
    {
        $ids = $b->templateIds;
        sort($ids);

        return $ids[0] ?? '';
    }
}
