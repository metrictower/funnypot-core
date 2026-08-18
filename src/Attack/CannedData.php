<?php

declare(strict_types=1);

namespace Funnypot\Attack;

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

    // Obviously-fake /etc/shadow: bcrypt-shaped but non-cracking hashes, standard field layout
    // (`:0:99999:7:::`) that LFI templates key on.
    public const SHADOW = "root:\$6\$fnpotsalt\$0000000000000000000000000000000000000000000000000000000000000000000000000000000000000:19000:0:99999:7:::\n"
        . "daemon:*:19000:0:99999:7:::\n"
        . "bin:*:19000:0:99999:7:::\n"
        . "www-data:*:19000:0:99999:7:::\n"
        . "sshd:*:19000:0:99999:7:::\n";

    public const GROUP = "root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nwww-data:x:33:\nmysql:x:114:\nsshd:x:115:\n";

    // /proc/self/environ — NUL-separated, as the real file is. Body-only (the NULs would trip
    // the header guard), carries PATH= / USER= markers.
    public const ENVIRON = "USER=www-data\x00HOME=/var/www\x00PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\x00PWD=/var/www/html\x00SHELL=/usr/sbin/nologin\x00";

    // No trailing newline: uid=... is the one marker meant to sit in a header value
    // (e.g. Confluence X-Cmd-Response), so it must stay CR/LF-free for the header guard.
    public const UID = "uid=0(root) gid=0(root) groups=0(root)";
}
