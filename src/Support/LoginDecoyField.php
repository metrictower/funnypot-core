<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

use Funnypot\Core\Config;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Template\DirectiveRenderer;

/**
 * The invisible login honeypot field (FP-0495): shared name-derivation + a DETECT-ONLY signal.
 *
 * Both login templates (route 50 GET form, attack 97 POST error page) render a hidden contact
 * <input> whose name is a {{pick:login_decoy_field:...}} — keyed on the RAW render seed the
 * templates are rendered with, `crc32(Config::seedFor($r))` (per-client-IP in prod, per-host by
 * default; no per-request nonce, so one source's GET-render name equals its POST-submit name). A
 * real browser/user never fills it (display:none wrapper + tabindex=-1 + aria-hidden +
 * autocomplete=off); a dumb form-filling bot does, so a non-empty value on submit is a
 * zero-false-positive scripted-bot signal.
 *
 * This helper is PURE and SERVE-NEUTRAL by construction: it produces no Verdict/Detection and never
 * enters classify()/respond() or the Observer serve veto, so the served login page is byte-identical
 * whether or not the field is filled — it never blocks. The store-owning tier (the funnypot-app
 * controller for the dedicated box; the funnypot-wordpress plugin for a real WP install) calls
 * isTripped() OUTSIDE the serve decision and appends the hit to its own store; core owns the
 * detection LOGIC, the caller owns the store.
 *
 * Render<->detect agreement is the make-or-break: DIRECTIVE is the single source of truth the
 * templates carry verbatim, and expectedName() renders that SAME literal through the SAME renderer
 * with the SAME `crc32($c->seedFor($r))` seed the render path used, so the name matches by
 * construction. The submitted value is read for an empty/non-empty boolean only and is NEVER
 * returned or reflected (mirrors the log/pwd never-reflected invariant of attack rule 97).
 */
final class LoginDecoyField
{
    /**
     * The exact {{pick}} directive both login templates carry — the ONE source of truth for the
     * field name. A core test pins that both compiled login bodies contain this literal, so the
     * render side and this detect side can never drift. The KEY (`login_decoy_field`) makes route 50
     * and attack 97 agree on one name at a given seed; the closed list is ordinary contact-field
     * names (none a known honeypot bait name, none reusing another plugin's field, none carrying a
     * honeypot/trap/spam self-unmask token).
     */
    public const DIRECTIVE = '{{pick:login_decoy_field:contact_phone,company_fax,alt_email,secondary_email,office_ext,mobile_alt}}';

    /** Bounded pair scan over rawBody — a form-decode never inspects more than this many fields. */
    private const MAX_PAIRS = 256;

    private function __construct()
    {
    }

    /**
     * The decoy field name for THIS request, rendered from DIRECTIVE with the identical render seed
     * the two login templates use: `crc32($c->seedFor($r))`. Passing a renderer is optional — the
     * {{pick}} branch keys only on that seed (never on the persona/deploy identity seed), so any
     * DirectiveRenderer resolves the same name; a caller may pass the renderer it already built.
     */
    public static function expectedName(RequestContext $r, Config $c, ?DirectiveRenderer $renderer = null): string
    {
        $renderer = $renderer ?? new DirectiveRenderer();

        return $renderer->render(self::DIRECTIVE, [], crc32($c->seedFor($r)));
    }

    /**
     * True iff the request's form body carries the decoy field with a non-empty value — a scripted
     * bot filled a field no real user can see. The value is used for the boolean only and is never
     * returned or reflected. Pure string work over $r->rawBody: no I/O, no state, no Verdict touch.
     */
    public static function isTripped(RequestContext $r, Config $c, ?DirectiveRenderer $renderer = null): bool
    {
        $body = $r->rawBody;
        if ($body === null || $body === '') {
            return false;
        }

        $name = self::expectedName($r, $c, $renderer);
        if ($name === '') {
            return false;
        }

        return self::formFieldNonEmpty($body, $name);
    }

    /**
     * Bounded, allocation-light form-decode: is $name present in the urlencoded $body with a value
     * that is non-empty after trimming? Reads keys/values with the same %XX/+ decoding a real form
     * sink applies. The decoded value is inspected only for emptiness, never kept.
     */
    private static function formFieldNonEmpty(string $body, string $name): bool
    {
        $pairs = explode('&', $body);
        $scanned = 0;
        foreach ($pairs as $pair) {
            if (++$scanned > self::MAX_PAIRS) {
                break;
            }
            if ($pair === '') {
                continue;
            }
            $eq = strpos($pair, '=');
            if ($eq === false) {
                continue;
            }
            $key = urldecode(substr($pair, 0, $eq));
            if ($key !== $name) {
                continue;
            }
            $value = urldecode(substr($pair, $eq + 1));

            return trim($value) !== '';
        }

        return false;
    }
}
