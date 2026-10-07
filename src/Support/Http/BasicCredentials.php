<?php

declare(strict_types=1);

namespace Funnypot\Core\Support\Http;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\BoundedInspection;

/**
 * FP-0007 — a small, pure HTTP Basic credential parser for the `basic` decoy-session mode (the Tomcat
 * Manager front door). It decides only whether a request carries a WELL-FORMED, PLAUSIBLE Basic
 * credential; it never compares the password against anything real (accept-any is deliberate and stays
 * under the activation decision). It throws nothing, logs nothing, and reflects nothing: a malformed or
 * oversize header yields null and the caller declines to the 401 challenge.
 *
 * Deliberately strict so a garbage Authorization header cannot reach a renderer:
 *  - exactly `Basic SP <token>` — one scheme, one space, no comma/fold/second scheme;
 *  - the encoded token is capped before a STRICT base64_decode (invalid alphabet ⇒ null);
 *  - exactly one colon splits username from password;
 *  - username 1–64 bytes in [A-Za-z0-9_.@-], password 1–128 bytes, neither carrying a control byte or NUL.
 */
final class BasicCredentials
{
    /** Cap the base64 token before decode — a real `user:pass` (≤64 + 1 + ≤128) base64-encodes well under this. */
    private const MAX_TOKEN_BYTES = 512;

    /**
     * The raw `Authorization` header value, read case-insensitively (BoundedInspection mirrors a real
     * server's header lookup). '' when absent or the request is null — the caller reads '' as "no explicit
     * Authorization, fall back to a verified cookie".
     */
    public static function authorization(?RequestContext $r): string
    {
        if ($r === null) {
            return '';
        }

        return BoundedInspection::headerValue($r->headers, 'Authorization');
    }

    /**
     * Parse a `Basic` Authorization value into {username, password}, or null on any malformed/implausible
     * input. Pure and throw-free.
     *
     * @return array{username:string,password:string}|null
     */
    public static function parse(string $authorization): ?array
    {
        // Exactly "Basic " + a single base64 token: one space, standard alphabet, optional padding, and
        // nothing else (no comma, fold, or a second scheme). Case-insensitive scheme name only.
        if (preg_match('/^Basic ([A-Za-z0-9+\/]+={0,2})$/i', $authorization, $m) !== 1) {
            return null;
        }
        $token = $m[1];
        if (strlen($token) > self::MAX_TOKEN_BYTES) {
            return null;
        }

        $decoded = base64_decode($token, true);
        if ($decoded === false) {
            return null;
        }

        // Exactly one colon splits username from password (the password itself may not contain a colon in
        // this strict parser — a Basic password with a colon is rare and rejecting it fails closed, never open).
        $colon = strpos($decoded, ':');
        if ($colon === false) {
            return null;
        }
        $username = substr($decoded, 0, $colon);
        $password = substr($decoded, $colon + 1);
        if (strpos($password, ':') !== false) {
            return null;
        }

        if (preg_match('/^[A-Za-z0-9_.@-]{1,64}$/', $username) !== 1) {
            return null;
        }
        if ($password === '' || strlen($password) > 128) {
            return null;
        }
        // No control byte or NUL anywhere (username is already alphabet-bounded; password is the open field).
        if (preg_match('/[\x00-\x1f\x7f]/', $password) === 1) {
            return null;
        }

        return ['username' => $username, 'password' => $password];
    }
}
