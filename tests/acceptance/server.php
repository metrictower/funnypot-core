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

use Funnypot\Core\Config;
use Funnypot\Core\Http\ResponseEmitter;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;

$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';

$store = PhpArrayStore::fromFile($root . '/resources/compiled/nuclei-index.full.php');

// Fully-open respond config so the harness certifies synthesis, not gating: respond
// mode on, gate always open, fixed persona for reproducible bundle selection. The
// response style is taken from NI_STYLE so the harness can certify every style really
// fires nuclei (minimal | realistic | taunt).
$style = getenv('NI_STYLE') ?: 'minimal';
$config = new Config(
    'respond',                                                                          // mode
    static function (RequestContext $r): bool { return true; },                          // gate
    'any',                                                                              // pathScope
    static function (RequestContext $r): string { return 'acceptance-fixed-persona'; }, // personaSeed
    'coherent',                                                                         // personaBreadth
    $style                                                                              // responseStyle
);

// NI_REFLECT=1 arms the request-authorized reflector lane (tests/acceptance/run-reflect.sh): the
// attack tier on, the origin asserted isolated, and an authorizer that treats every request as
// evidence. That authorizer is valid ONLY here — a throwaway loopback responder with no operator
// plane behind it; a real adapter must derive its answer from a server-side fact a client cannot
// supply. Off (the default) the golden job's config and served bytes are untouched.
if (getenv('NI_REFLECT') === '1') {
    $config->attackEmulation = true;
    $config->isolatedOrigin = true;
    $config->reflectorAuthorizer = static function (RequestContext $r, string $class): bool { return true; };
}

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
