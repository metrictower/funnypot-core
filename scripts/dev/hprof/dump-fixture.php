#!/usr/bin/env php
<?php

/**
 * Write the spring_hprof_v1 heap-dump decoy for one persona seed to a file and print, as JSON, the
 * persona secrets it plants — the inputs the opt-in interop harness (check-mat.sh) greps for. Dev-only.
 *
 *   php scripts/dev/hprof/dump-fixture.php --seed=<material> --out=/tmp/heapdump.hprof
 */

declare(strict_types=1);

use Funnypot\Core\Response\SpringHprofGenerator;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Template\DirectiveRenderer;

require dirname(__DIR__, 3) . '/vendor/autoload.php';

$material = 'fixture';
$out = '';
foreach (array_slice($argv, 1) as $arg) {
    if (strncmp($arg, '--seed=', 7) === 0) {
        $material = substr($arg, 7);
    } elseif (strncmp($arg, '--out=', 6) === 0) {
        $out = substr($arg, 6);
    }
}
if ($out === '') {
    fwrite(STDERR, "usage: dump-fixture.php --seed=<material> --out=<file.hprof>\n");
    exit(2);
}

$personaSeed = PersonaIdentity::seedFromMaterial($material);
$bytes = (new SpringHprofGenerator())->generate(new DirectiveRenderer($personaSeed), 0);
if ($bytes === null) {
    fwrite(STDERR, "generator declined\n");
    exit(1);
}
if (file_put_contents($out, $bytes) !== strlen($bytes)) {
    fwrite(STDERR, "could not write {$out}\n");
    exit(1);
}

$p = PersonaIdentity::fromSeed($personaSeed);
$secrets = [];
foreach (['db.password', 'cloud.aws.accessKeyId', 'cloud.aws.secretKey', 'user.admin.username', 'user.admin.password', 'secret.jwt'] as $field) {
    $secrets[$field] = (string) $p->field($field);
}
$secrets['jdbc'] = 'jdbc:postgresql://' . $p->field('db.host') . ':5432/' . $p->field('db.name');
$secrets['eureka'] = 'http://' . $p->field('user.admin.username') . ':' . $p->field('user.admin.password') . '@discovery.internal:8761/eureka/';

echo json_encode(['file' => $out, 'bytes' => strlen($bytes), 'secrets' => $secrets], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
