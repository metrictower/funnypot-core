<?php

declare(strict_types=1);

namespace Funnypot\Laravel;

use Funnypot\SynthesizedResponse;

/**
 * SynthesizedResponse -> Illuminate\Http\Response. See LaravelRequestMapper for
 * why Illuminate\* is referenced by FQCN only.
 */
final class LaravelResponseMapper
{
    public static function map(SynthesizedResponse $response): \Illuminate\Http\Response
    {
        $headers = [];
        foreach ($response->headers as $name => $value) {
            // C8 defence-in-depth, mirroring Http\ResponseEmitter's guard.
            if (preg_match('/[\r\n\x00]/', (string) $name) === 1
                || preg_match('/[\r\n\x00]/', (string) $value) === 1) {
                continue;
            }
            $headers[$name] = $value;
        }

        return new \Illuminate\Http\Response($response->body, $response->status, $headers);
    }
}
