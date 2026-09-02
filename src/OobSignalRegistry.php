<?php

declare(strict_types=1);

namespace Funnypot\Core;

/**
 * The OOB / signal-only probe registry (FP-0256). One place every request-content signal
 * probe plugs into: classify() folds each returned match via foldOob(). Registering a new
 * signal-only detector (XXE-OOB, DNS-rebinding, generic-JNDI, …) is adding one guarded
 * block here — zero classify() changes.
 *
 * Probes here are SIGNAL-ONLY by contract: pure string / pattern matching over the
 * RequestContext — no I/O, no config, no state — and their output lives only in the
 * Detection (a logging / telemetry projection), never in a served byte. A fixed
 * registration order gives a deterministic match order (OAST before Log4Shell), so the
 * folded match array is stable for a given request.
 *
 * NOT subject to Config->ignoreTemplates: the ids minted here (oast-callback,
 * log4shell-jndi, log4shell-resolver) are registry ids, not store template ids, so
 * applyIgnore() never silences a folded signal match — matching today's OAST semantics.
 * Whether registry-match ids should ever be silenceable is a deliberate follow-up.
 */
final class OobSignalRegistry
{
    /** @return TemplateMatch[] zero, one, or two matches, in fixed probe order */
    public static function matches(RequestContext $r): array
    {
        $out = [];

        $family = OastProbe::detect($r);
        if ($family !== null) {
            // Per-family projection (FP-0257): OastProbe::matchFor maps the zone-family label to its
            // id / severity / tags — cloud-metadata is critical (SSRF target, id cloud-metadata-ssrf),
            // xxe-oob / jndi-oob / dns-rebinding carry their own ids, the collaborator families keep
            // the legacy oast-callback shape. Built here so the registry stays the one fold seam.
            $out[] = OastProbe::matchFor($family);
        }

        $mode = Log4ShellProbe::detect($r);
        if ($mode === Log4ShellProbe::CONFIRMED) {
            $out[] = new TemplateMatch(
                'log4shell-jndi',
                'critical',
                ['log4shell', 'jndi', 'oob'],
                'Log4Shell JNDI lookup probe'
            );
        } elseif ($mode === Log4ShellProbe::RESOLVER) {
            $out[] = new TemplateMatch(
                'log4shell-resolver',
                'high',
                ['log4shell', 'jndi', 'oob', 'resolver-only'],
                'Log4j lookup-resolver probe'
            );
        }

        return $out;
    }
}
