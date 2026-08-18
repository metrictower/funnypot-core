<?php

declare(strict_types=1);

namespace Funnypot\Laravel\Console;

/**
 * `php artisan funnypot:update` — thin wrapper around the package's own
 * `bin/funnypot compile` CLI (SPEC.md §4 "Updateability"). Shells out
 * rather than calling the Compiler in-process so a bad/huge corpus can't take
 * the web app down mid-request; the app only ever sees the already-written
 * resources/compiled/*.php once the subprocess exits cleanly.
 */
final class UpdateTemplatesCommand extends \Illuminate\Console\Command
{
    /** @var string */
    protected $signature = 'funnypot:update
        {templates : Path to a local nuclei-templates checkout (or its http/ subdir)}
        {--out= : Compiled index output path (defaults to resources/compiled/nuclei-index.full.php)}';

    /** @var string */
    protected $description = 'Recompile the funnypot template index from a nuclei-templates checkout.';

    public function handle(): int
    {
        $packageRoot = dirname(__DIR__, 3);
        $binary = $packageRoot . '/bin/funnypot';

        if (!is_file($binary)) {
            $this->error("funnypot binary not found at {$binary}.");

            return 1;
        }

        $templatesDir = (string) $this->argument('templates');
        $out = $this->option('out');
        $out = is_string($out) && $out !== '' ? $out : $packageRoot . '/resources/compiled/nuclei-index.full.php';

        $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($binary)
            . ' compile ' . escapeshellarg($templatesDir)
            . ' --out=' . escapeshellarg($out);

        $this->info("funnypot: {$command}");

        passthru($command, $exitCode);

        return (int) $exitCode;
    }
}
