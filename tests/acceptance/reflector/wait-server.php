<?php

declare(strict_types=1);

if ($argc !== 1) {
    fwrite(STDERR, "wait-server.php accepts no arguments\n");
    exit(2);
}

for ($attempt = 0; $attempt < 50; $attempt++) {
    $socket = @fsockopen('127.0.0.1', 8898, $errorNumber, $errorMessage, 0.1);
    if (is_resource($socket)) {
        fclose($socket);
        exit(0);
    }
    usleep(100000);
}

fwrite(STDERR, "loopback responder did not start\n");
exit(1);
