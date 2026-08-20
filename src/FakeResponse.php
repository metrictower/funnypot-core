<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * Policy-facing name for SynthesizedResponse (two-phase design §2.2 / decision M). The value
 * is unchanged — status, headers, body, satisfies — only the vocabulary matches §M. Every
 * existing use of SynthesizedResponse keeps compiling; new code may name it FakeResponse.
 *
 * A class alias (SynthesizedResponse is final and cannot be subclassed). Loading this file via
 * the autoloader registers the alias; the ::class reference triggers loading the original.
 */
class_alias(SynthesizedResponse::class, FakeResponse::class);
