<?php

declare(strict_types=1);

if ($argc !== 1) {
    fwrite(STDERR, "download.php accepts no arguments\n");
    exit(2);
}

$pins = json_decode((string) file_get_contents('/opt/reflector/versions.json'), true);
if (!is_array($pins) || json_last_error() !== JSON_ERROR_NONE) {
    throw new RuntimeException('malformed versions.json');
}

foreach (['nuclei', 'dalfox'] as $tool) {
    $pin = $pins[$tool];
    $destination = '/opt/reflector/downloads/' . $pin['archive_name'];
    $source = @fopen($pin['archive_url'], 'rb');
    $target = @fopen($destination, 'xb');
    if ($source === false || $target === false) {
        throw new RuntimeException('cannot open pinned ' . $tool . ' archive');
    }
    $hash = hash_init('sha256');
    $bytes = 0;
    while (!feof($source)) {
        $chunk = fread($source, 65536);
        if (!is_string($chunk)) {
            throw new RuntimeException('cannot read pinned ' . $tool . ' archive');
        }
        $bytes += strlen($chunk);
        if ($bytes > (int) $pin['archive_bytes']) {
            throw new RuntimeException($tool . ' archive exceeds pinned size');
        }
        hash_update($hash, $chunk);
        if ($chunk !== '' && fwrite($target, $chunk) !== strlen($chunk)) {
            throw new RuntimeException('cannot write pinned ' . $tool . ' archive');
        }
    }
    if (!fflush($target)) {
        throw new RuntimeException('cannot flush pinned ' . $tool . ' archive');
    }
    fclose($source);
    fclose($target);
    if ($bytes !== (int) $pin['archive_bytes'] || hash_final($hash) !== $pin['archive_sha256']) {
        throw new RuntimeException($tool . ' archive pin mismatch');
    }
}
