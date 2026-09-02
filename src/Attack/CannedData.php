<?php

declare(strict_types=1);

namespace Funnypot\Core\Attack;

use Funnypot\Core\Support\SubSeed;

/**
 * Canned fake output shared by attack signatures — the standard markers nuclei's LFI / RCE templates
 * look for. Static in shape, obviously-fake, never real data.
 *
 * PER-DEPLOY SEEDED (FP-0277). Each surface is a pure static function of the deploy seed (via
 * {@see SubSeed}, namespace {@see SubSeed::NS_CANNED}) rather than one fleet-wide constant blob — the
 * byte-identical /etc/passwd, /etc/shadow, SSH key body, hostname and /proc/self/environ that used to
 * ship on every deploy were the strongest cross-deploy correlation tell. The load-bearing
 * exploit-confirmation markers scanners key on are emitted VERBATIM as literals at every seed (see the
 * *_HEAD / *_AGING consts below); only the surrounding fleet-correlation filler is seed-varied.
 *
 * DETERMINISM. `served = f(deploySeed)`: no clock, counter, CSPRNG, request byte or env leaks in (the
 * SubSeed signatures admit none). Within a deploy the seed is fixed, so every surface re-renders
 * byte-identically; across deploys a different seed yields different filler. This is what the FP-0276
 * seeded-render gate's render-twice determinism + cross-deploy checks rely on.
 *
 * 32-bit safe: only SubSeed::index/chars/pick/permute/subset/reroll are used for served offsets and
 * strings (all width-safe via SeededIndex::fromHex); SubSeed::int() is never used here (it is
 * 64-bit-only and would derive a served offset). PHP 7.3-safe.
 */
final class CannedData
{
    // --- load-bearing marker literals (emitted verbatim at EVERY seed) ---------------------------
    // The /etc/passwd head line: satisfies both the `root:x:0:0` and the trailing-colon `root:x:0:0:`
    // scanner tokens (expect: pins in 31-lfi-unix / 20-xxe / 10-shellshock / 952-crs-lfi + nuclei bw/rx).
    private const PASSWD_HEAD = "root:x:0:0:root:/root:/bin/bash\n";
    // The /etc/group head line (expect: pin in 29-lfi-group: `root:x:0:`).
    private const GROUP_HEAD = "root:x:0:\n";
    // The id-command head (expect: pins in 41-cmdi-unix / 05-confluence / 12-struts / 46-glastopf +
    // nuclei bw). MUST stay CR/LF/NUL-free — it is the one marker meant to sit in a header value
    // (e.g. Confluence X-Cmd-Response), so the varied supplementary-group tail is CR/LF/NUL-free too.
    private const UID_HEAD = 'uid=0(root) gid=0(root) groups=0(root)';
    // The /etc/shadow aging-field tail LFI templates key on (expect: pin in 28-lfi-shadow).
    private const SHADOW_AGING = ':0:99999:7:::';
    // OpenSSH envelope (expect: pin in 21-lfi-sshkey).
    private const SSH_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    private const SSH_END = "-----END OPENSSH PRIVATE KEY-----\n";

    // --- alphabets ------------------------------------------------------------------------------
    // sha512-crypt ($6$) base64 alphabet (./0-9A-Za-z) — the class CannedDataTest's shape regex pins.
    private const CRYPT_ALPHABET = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    // Standard base64 alphabet for the inert SSH key body.
    private const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    // 12 lines at 70 chars/line = 800, a multiple of 4 so the joined body is strict-base64-decodable.
    private const SSH_BODY_LEN = 800;

    public const WININI = "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n";

    // The UNSIGNED portion (base64url header '.' payload) of a fake in-pod Kubernetes service-account
    // token (/var/run/secrets/kubernetes.io/serviceaccount/token). The template appends a seed-derived
    // signature ('.'.{{fake.k8s_sig:b64url}}…) so no two deployments serve a byte-identical token — a
    // shared constant token would let an attacker cluster the honeypot. Header is RS256 with a
    // realistic (non-self-identifying) kid; payload carries the standard default:default serviceaccount
    // claims a leaked token would. base64url, no padding. Nothing here verifies against a real key.
    // Left constant (EPIC-scope deferral, FP-0258 plan line 191): the SERVED token already varies per
    // deploy via the seed-derived signature, and varying header/payload would break the seed-invariance
    // pins at TraversalReadTest and risk the `system:serviceaccount:default:default` scanner marker.
    public const K8S_SA_UNSIGNED = 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImZnUmR4R29RakFoX0p1Wm9fN2V4LUNRZXpUY3dQc2lrYU1ybnhtaWpqQjQifQ'
        . '.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCIsImF1ZCI6WyJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMiXSwiZXhwIjoyMDAwMDAwMDAwLCJpYXQiOjE2MDAwMDAwMDAsImt1YmVybmV0ZXMuaW8vbmFtZXNwYWNlIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIn0';

    /**
     * The single lookup DirectiveRenderer calls for a `{{canned.<key>}}` directive. Returns null for an
     * unknown key so the renderer's `|`-alternatives still cascade (unchanged fail-safe).
     */
    public static function render(string $key, int $seed): ?string
    {
        switch ($key) {
            case 'passwd':
                return self::passwd($seed);
            case 'shadow':
                return self::shadow($seed);
            case 'group':
                return self::group($seed);
            case 'hostname':
                return self::hostname($seed);
            case 'ssh_private_key':
                return self::sshPrivateKey($seed);
            case 'environ':
                return self::environ($seed);
            case 'uid':
                return self::uid($seed);
            case 'winini':
                return self::winini($seed);
            case 'k8s_sa_unsigned':
                return self::k8sSaUnsigned($seed);
            default:
                return null;
        }
    }

    /**
     * A fake /etc/passwd. The root head line is verbatim (the `root:x:0:0` marker); the service-account
     * tail is a seeded subset (set + order) of a realistic pool, each with a plausible fixed uid/gid and
     * a seed-picked nologin shell. uids/gids are <= 999 so no bare `\b9\d{5}\b` denylist token can form.
     */
    public static function passwd(int $seed): string
    {
        $out = self::PASSWD_HEAD;
        foreach (self::accounts($seed) as $acct) {
            [$name, $uid, $gid, $gecos, $home] = $acct;
            $shell = SubSeed::pick(['/usr/sbin/nologin', '/bin/false'], $seed, SubSeed::NS_CANNED, 'passwd|shell|' . $name);
            $out .= $name . ':x:' . $uid . ':' . $gid . ':' . $gecos . ':' . $home . ':' . $shell . "\n";
        }

        return $out;
    }

    /**
     * A fake /etc/shadow. The root line reconstructs the exact `root:$6$<salt>$<hash>:<date>:0:99999:7:::`
     * layout the shape regex + the `:0:99999:7:::` marker pin, with a seeded 12-char salt and 86-char
     * crypt-alphabet hash body — a derived string, never a real crypt(), so it is inert (cracks to
     * nothing). The salt/hash go through SubSeed::reroll so a `.`/`/`-bounded 6-digit run in the
     * rendered line can never trip the fingerprint denylist (a class the static gate cannot see). The
     * non-root lines are the same coherent account subset as passwd, each a locked `*` password.
     */
    public static function shadow(int $seed): string
    {
        $out = SubSeed::reroll('shadow|root', static function (string $f) use ($seed): string {
            $salt = SubSeed::chars($seed, SubSeed::NS_CANNED, $f . '|salt', self::CRYPT_ALPHABET, 12);
            $hash = SubSeed::chars($seed, SubSeed::NS_CANNED, $f . '|hash', self::CRYPT_ALPHABET, 86);
            $date = 19000 + SubSeed::index($seed, SubSeed::NS_CANNED, $f . '|date', 900);

            return 'root:$6$' . $salt . '$' . $hash . ':' . $date . self::SHADOW_AGING . "\n";
        });
        foreach (self::accounts($seed) as $acct) {
            $name = $acct[0];
            $date = 19000 + SubSeed::index($seed, SubSeed::NS_CANNED, 'shadow|date|' . $name, 900);
            $out .= $name . ':*:' . $date . ':0:99999:7:::' . "\n";
        }

        return $out;
    }

    /**
     * A fake /etc/group. The root head line is verbatim (the `root:x:0:` marker); the tail is the SAME
     * coherent account subset as passwd (a group member is an account that exists), each `name:x:<gid>:`.
     */
    public static function group(int $seed): string
    {
        $out = self::GROUP_HEAD;
        foreach (self::accounts($seed) as $acct) {
            [$name, , $gid] = $acct;
            $out .= $name . ':x:' . $gid . ':' . "\n";
        }

        return $out;
    }

    /**
     * A single plausible hostname line `role-env-NN\n`, seed-composed. `web-prod-01` is NOT a
     * cross-fleet scanner marker (absent from the nuclei index and CRS corpus), so the whole string may
     * vary; the shape stays `^[a-z0-9][a-z0-9.-]{1,62}\n$`.
     */
    public static function hostname(int $seed): string
    {
        $role = SubSeed::pick(['web', 'app', 'api', 'db', 'cache', 'worker', 'edge', 'node', 'svc', 'lb'], $seed, SubSeed::NS_CANNED, 'hostname|role');
        $env = SubSeed::pick(['prod', 'stg', 'dev', 'qa', 'ops', 'infra'], $seed, SubSeed::NS_CANNED, 'hostname|env');
        $nn = sprintf('%02d', 1 + SubSeed::index($seed, SubSeed::NS_CANNED, 'hostname|nn', 42));

        return $role . '-' . $env . '-' . $nn . "\n";
    }

    /**
     * An inert SSH private key: the OpenSSH envelope (the marker) wrapping a seeded base64 body wrapped
     * to 12 lines of 70 chars. The body is a derived string, not a real key — the guard rerolls if the
     * decoded blob would begin with the `openssh-key-v1\0` magic, so it authenticates nowhere. The
     * reject predicate runs on the WHOLE line-wrapped PEM (not the raw run): a `\b9\d{5}\b` denylist
     * token can straddle a 70-char wrap boundary, invisible to a check on the un-wrapped body.
     */
    public static function sshPrivateKey(int $seed): string
    {
        return SubSeed::reroll(
            'ssh|body',
            static function (string $f) use ($seed): string {
                $raw = SubSeed::chars($seed, SubSeed::NS_CANNED, $f, self::B64_ALPHABET, self::SSH_BODY_LEN);
                $wrapped = rtrim(chunk_split($raw, 70, "\n"), "\n");

                return self::SSH_BEGIN . $wrapped . "\n" . self::SSH_END;
            },
            static function (string $pem): bool {
                if (SubSeed::hitsDeniedDigits($pem)) {
                    return true;
                }
                if (preg_match('/-----BEGIN OPENSSH PRIVATE KEY-----\n(.*)\n-----END/s', $pem, $m) === 1) {
                    $blob = base64_decode(str_replace("\n", '', $m[1]), true);
                    if ($blob !== false && strncmp($blob, "openssh-key-v1\0", 15) === 0) {
                        return true; // would be a structurally valid (non-inert) key — reroll
                    }
                }

                return false;
            }
        );
    }

    /**
     * A fake /proc/self/environ — NUL-separated, body-only (the NULs would trip the header guard).
     * Keeps the USER= and PATH= markers; the var ORDER is seed-permuted and the PWD leaf is seed-picked.
     */
    public static function environ(int $seed): string
    {
        $leaf = SubSeed::pick(['html', 'public', 'current', 'htdocs', 'app', 'web', 'sites/default', 'releases/current'], $seed, SubSeed::NS_CANNED, 'environ|pwd');
        $vars = [
            'USER=www-data',
            'HOME=/var/www',
            'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'PWD=/var/www/' . $leaf,
            'SHELL=/usr/sbin/nologin',
        ];
        /** @var list<string> $vars */
        $vars = SubSeed::permute($vars, $seed, SubSeed::NS_CANNED, 'environ|order');

        return implode("\x00", $vars) . "\x00";
    }

    /**
     * The id-command output. The head is verbatim (`uid=0(root) gid=0(root) groups=0(root)` — the
     * marker); a seeded subset of supplementary groups is appended as `,<gid>(<name>)`. Stays
     * CR/LF/NUL-free (the head must sit in a header value): every pool literal + gid is by construction.
     */
    public static function uid(int $seed): string
    {
        $out = self::UID_HEAD;
        $pool = [[4, 'adm'], [24, 'cdrom'], [27, 'sudo'], [30, 'dip'], [46, 'plugdev'], [100, 'users'], [999, 'docker']];
        $n = SubSeed::index($seed, SubSeed::NS_CANNED, 'uid|n', 4); // 0-3 extra groups
        foreach (SubSeed::subset($pool, $n, $seed, SubSeed::NS_CANNED, 'uid|groups') as $grp) {
            [$gid, $name] = $grp;
            $out .= ',' . $gid . '(' . $name . ')';
        }

        return $out;
    }

    /** win.ini — Windows, out of the ticket's field list; unchanged (the `[extensions]` marker). */
    public static function winini(int $seed): string
    {
        return self::WININI;
    }

    /** The fake in-pod k8s SA token's unsigned portion — unchanged (epic-scope deferral; see the const). */
    public static function k8sSaUnsigned(int $seed): string
    {
        return self::K8S_SA_UNSIGNED;
    }

    /**
     * The coherent per-deploy service-account subset shared by passwd/shadow/group, so a group member
     * and its shadow line always correspond to an account that appears in passwd. A seeded subset
     * (set + order) of 6-9 accounts from a realistic pool; each tuple is [name, uid, gid, gecos, home]
     * with fixed, plausible ids (daemon/bin/sys keep their classic numbers) so no served number can
     * form a denylist token.
     *
     * @return list<array{0:string,1:int,2:int,3:string,4:string}>
     */
    private static function accounts(int $seed): array
    {
        $pool = [
            ['daemon', 1, 1, 'daemon', '/usr/sbin'],
            ['bin', 2, 2, 'bin', '/bin'],
            ['sys', 3, 3, 'sys', '/dev'],
            ['sync', 4, 65534, 'sync', '/bin'],
            ['games', 5, 60, 'games', '/usr/games'],
            ['man', 6, 12, 'man', '/var/cache/man'],
            ['lp', 7, 7, 'lp', '/var/spool/lpd'],
            ['mail', 8, 8, 'mail', '/var/mail'],
            ['news', 9, 9, 'news', '/var/spool/news'],
            ['www-data', 33, 33, 'www-data', '/var/www'],
            ['backup', 34, 34, 'backup', '/var/backups'],
            ['irc', 39, 39, 'ircd', '/run/ircd'],
            ['mysql', 110, 113, 'MySQL Server,,,', '/nonexistent'],
            ['postgres', 111, 117, 'PostgreSQL administrator', '/var/lib/postgresql'],
            ['redis', 112, 118, 'redis', '/var/lib/redis'],
            ['sshd', 113, 65534, '', '/run/sshd'],
            ['nobody', 65534, 65534, 'nobody', '/nonexistent'],
        ];
        $k = 6 + SubSeed::index($seed, SubSeed::NS_CANNED, 'passwd|k', 4); // 6-9 accounts

        /** @var list<array{0:string,1:int,2:int,3:string,4:string}> $subset */
        $subset = SubSeed::subset($pool, $k, $seed, SubSeed::NS_CANNED, 'passwd|users');

        return $subset;
    }
}
