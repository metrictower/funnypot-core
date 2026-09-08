<?php

declare(strict_types=1);

use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\BoundedInspection;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

/** @return float */
function inputCeilingMedian(array $samples)
{
    sort($samples, SORT_NUMERIC);
    $count = count($samples);
    $middle = intdiv($count, 2);

    return $count % 2 === 0
        ? ($samples[$middle - 1] + $samples[$middle]) / 2
        : $samples[$middle];
}

printf(
    "php=%s pcre=%s jit=%s iterations=%d\n",
    PHP_VERSION,
    defined('PCRE_VERSION') ? PCRE_VERSION : 'unknown',
    (string) ini_get('pcre.jit'),
    200
);

foreach ([4096, 8192, 65536] as $bytes) {
    $target = str_repeat('t', $bytes);
    $body = substr(str_repeat('%2525', (int) ceil($bytes / 5)), 0, $bytes);
    $request = new RequestContext('POST', $target, '', [], $body);
    $samples = [];
    $beforePeak = memory_get_peak_usage(false);
    $subjectBytes = 0;

    for ($i = 0; $i < 200; $i++) {
        $start = hrtime(true);
        $accepted = BoundedInspection::targetAccepted($request);
        $subjectBytes = strlen(BoundedInspection::requestSubject($request));
        $samples[] = (hrtime(true) - $start) / 1000;
    }

    printf(
        "target_bytes=%d accepted=%s subject_bytes=%d median_us=%.3f peak_delta_bytes=%d\n",
        $bytes,
        $accepted ? 'yes' : 'no',
        $subjectBytes,
        inputCeilingMedian($samples),
        memory_get_peak_usage(false) - $beforePeak
    );
}
