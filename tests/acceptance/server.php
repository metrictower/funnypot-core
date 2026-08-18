<?php

declare(strict_types=1);

/**
 * Acceptance router for `php -S`. Backs a live host with the FULL compiled index
 * so real nuclei can be run against it (SPEC §6 — the only non-circular proof).
 *
 * Every request: build a RequestContext from globals, ask the inverter to
 * respond(), and either emit the synthesized response or serve a plain 404 —
 * exactly the drop-in shape an app's 404 handler would use.
 *
 *   php -S 127.0.0.1:8899 tests/acceptance/server.php
 */

use Funnypot\Config;
use Funnypot\Http\ResponseEmitter;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;

$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';

$store = PhpArrayStore::fromFile($root . '/resources/compiled/nuclei-index.full.php');

// Fully-open respond config so the harness certifies synthesis, not gating: respond
// mode on, gate always open, fixed persona for reproducible bundle selection. The
// response style is taken from NI_STYLE so the harness can certify every style really
// fires nuclei (minimal | realistic | taunt).
$style = getenv('NI_STYLE') ?: 'minimal';
$config = new Config(
    mode: 'respond',
    gate: static fn (RequestContext $r): bool => true,
    pathScope: 'any',
    personaSeed: static fn (RequestContext $r): string => 'acceptance-fixed-persona',
    responseStyle: $style
);
$inverter = new Honeypot($store, $config);

$response = $inverter->respond(RequestContext::fromGlobals());

if ($response === null) {
    http_response_code(404);
    header('Content-Type: text/plain');
    echo "Not Found\n";

    return true;
}

ResponseEmitter::emit($response);

return true;
