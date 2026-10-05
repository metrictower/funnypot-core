<?php

declare(strict_types=1);

if ($argc < 3 || strpos($argv[1], '/output/') !== 0 || basename($argv[1]) !== 'invocation.json') {
    fwrite(STDERR, "invalid invocation recorder arguments\n");
    exit(2);
}

$encoded = json_encode(array_slice($argv, 2), JSON_UNESCAPED_SLASHES);
if (!is_string($encoded) || file_put_contents($argv[1], $encoded . "\n", LOCK_EX) === false) {
    fwrite(STDERR, "cannot record scanner invocation\n");
    exit(2);
}
