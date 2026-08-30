<?php

declare(strict_types=1);

namespace Funnypot\Core\Attack;

/**
 * Canned fake output shared by attack signatures — the standard markers nuclei's
 * LFI / RCE templates look for. Static, obviously-fake, never real data.
 */
final class CannedData
{
    public const PASSWD = "root:x:0:0:root:/root:/bin/bash\n"
        . "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        . "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        . "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        . "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        . "mysql:x:110:113:MySQL Server,,,:/nonexistent:/bin/false\n"
        . "sshd:x:112:65534::/run/sshd:/usr/sbin/nologin\n";

    public const WININI = "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n";

    // Inert /etc/shadow: sha512-crypt ($6$)-shaped root hash with a random salt + random 86-char
    // hash body — it is the crypt of no password, so it never cracks, and carries no brand. The
    // standard aging field layout (`:0:99999:7:::`) is what LFI templates key on.
    public const SHADOW = "root:\$6\$7Wb7FffMXczv\$LxmVWD7zqGsIdQ5qFt9.5b6HKWD9LMnsrbt1ouC1gDPqtgwd6mEf1TU8.aO6Bsx52mXBdX0FxDp/YImFwod79t:19710:0:99999:7:::\n"
        . "daemon:*:19000:0:99999:7:::\n"
        . "bin:*:19000:0:99999:7:::\n"
        . "www-data:*:19000:0:99999:7:::\n"
        . "sshd:*:19000:0:99999:7:::\n";

    public const GROUP = "root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nwww-data:x:33:\nmysql:x:114:\nsshd:x:115:\n";

    // /etc/hostname is a single short hostname line — an LFI target returns this, not passwd.
    public const HOSTNAME = "web-prod-01\n";

    // Inert SSH private key served for an id_rsa/.ssh LFI target — a syntactically valid OpenSSH
    // envelope wrapping a random base64 body. It decodes to no key structure, so it authenticates
    // nowhere; it exists only to answer with a key-shaped file instead of passwd.
    public const SSH_PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        . "LMAasjSpVCY1cOJndvhPHAEI0g2iviIFohWOPN80HajV7aNw7z8VuRvR1J6n2WADviXEqT\n"
        . "DoCHoop8drzi/NcFTCRPzQP8soCQnz0N4b2k8lk/lg+SVsOnnZBGyLCzFY2fKOVYkcrhTO\n"
        . "Kl8t1Z5o3vOvkQCkEwYPA5Yn/l5qZ2Tl7uJKMtKure8YsjCKscu0meS6KTOy0VHA4PhYz/\n"
        . "3NRVxRRjlnZAHQPRcH973cf9Mv3m2xQoujtNtP4UJp+Yt4XeZlXcUw9Fr7mg+FFTr2h6yH\n"
        . "NYBAW8Yo5T4hJOnvoJtYBwvaSTLJ2gX/0l3Uo1dx8DT26xJwgrbL1U9IdcgM8lHSa7Jmt+\n"
        . "9N0nkRfzey1H2IQRD4KglkNHLu+IMNln5qKP0ThL1i/Fkb8816hnMR/c8h3/04eQGMXr39\n"
        . "J9SshaiC02WRbwMKzA33G1eBBMnQFjJFG0/ZXkxNMza5z5mNKyarhGdglKVcF0SVeOU71t\n"
        . "yDpc+bVz97NtfNAbw1PHyeuTDGiUgB57fSYHsinamZH4/AYPPLeXJKdpdhV1uMqjo1SavI\n"
        . "/Rdmdo0OLqlMZ8Te52gmGKqAvklw4IoEHwN186EHwW27rqN2yWLDenx4je0F0Id2uSuTUB\n"
        . "/G6H/C0QgtH6ou8bWunKKHUdpqmhMWhCycPc5GuBYbIr8aetH94mzVxH8RQV8XBu2wHRW6\n"
        . "f+tsOhziOp8L1d0SvF/CD555OiK2zQg1o/1fU8KilADNommJshFNIJmleM4VoF6xnp1YUB\n"
        . "ubpYKEybcqR1dY2hA1+Uw94XnxBMF3\n"
        . "-----END OPENSSH PRIVATE KEY-----\n";

    // /proc/self/environ — NUL-separated, as the real file is. Body-only (the NULs would trip
    // the header guard), carries PATH= / USER= markers.
    public const ENVIRON = "USER=www-data\x00HOME=/var/www\x00PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\x00PWD=/var/www/html\x00SHELL=/usr/sbin/nologin\x00";

    // No trailing newline: uid=... is the one marker meant to sit in a header value
    // (e.g. Confluence X-Cmd-Response), so it must stay CR/LF-free for the header guard.
    public const UID = "uid=0(root) gid=0(root) groups=0(root)";

    // The UNSIGNED portion (base64url header '.' payload) of a fake in-pod Kubernetes service-account
    // token (/var/run/secrets/kubernetes.io/serviceaccount/token). The template appends a seed-derived
    // signature ('.'.{{fake.k8s_sig:b64url}}…) so no two deployments serve a byte-identical token — a
    // shared constant token would let an attacker cluster the honeypot. Header is RS256 with a
    // realistic (non-self-identifying) kid; payload carries the standard default:default serviceaccount
    // claims a leaked token would. base64url, no padding. Nothing here verifies against a real key.
    public const K8S_SA_UNSIGNED = 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImZnUmR4R29RakFoX0p1Wm9fN2V4LUNRZXpUY3dQc2lrYU1ybnhtaWpqQjQifQ'
        . '.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCIsImF1ZCI6WyJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMiXSwiZXhwIjoyMDAwMDAwMDAwLCJpYXQiOjE2MDAwMDAwMDAsImt1YmVybmV0ZXMuaW8vbmFtZXNwYWNlIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIn0';
}
