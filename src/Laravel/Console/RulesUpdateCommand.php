<?php

declare(strict_types=1);

namespace Funnypot\Laravel\Console;

use Funnypot\Rules\RulesUpdater;

/**
 * `php artisan funnypot:rules-update` — fetch + verify + hot-swap a signed rules release into
 * the configured data dir, no composer update. Unlike UpdateTemplatesCommand (which passthru's
 * to a heavy in-process compile), this calls the RulesUpdater PHP API in-process: an HTTPS
 * fetch, one signature check, and file I/O — nothing worth isolating into a subprocess.
 *
 * Exit codes: 0 = rules are good (updated / already current / rolled back); 1 = an update was
 * attempted and failed (rules unchanged — a scheduler ->onFailure() should alert, not page); the
 * honeypot stays up on the prior release either way. Also emits a STALE warning when the last
 * successful check is older than funnypot.rules.staleness_alarm_hours — a wedged updater goes
 * blind, and that must be loud.
 *
 * Illuminate is referenced by FQCN only (see FunnypotServiceProvider) so the package keeps no
 * hard Laravel dependency.
 */
final class RulesUpdateCommand extends \Illuminate\Console\Command
{
    /** @var string */
    protected $signature = 'funnypot:rules-update
        {--rollback : Roll back to a retained prior release instead of updating}
        {--to= : With --rollback, the exact version to roll back to (default: previous)}
        {--status : Print the installed rules status and exit}
        {--data-dir= : Override funnypot.rules.data_dir}';

    /** @var string */
    protected $description = 'Fetch and hot-swap a signed funnypot-rules release (no composer update).';

    public function handle(): int
    {
        /** @var array<string,mixed> $cfg */
        $cfg = (array) config('funnypot.rules', []);
        $dataDir = (string) ($this->option('data-dir') ?: ($cfg['data_dir'] ?? ''));

        if ($dataDir === '') {
            $this->error('funnypot.rules.data_dir is not configured; nothing to update. See docs/RULES-UPDATE.md.');

            return 1;
        }

        $updater = new RulesUpdater(
            $dataDir,
            (string) ($cfg['channel'] ?? 'stable'),
            ($cfg['pinned_version'] ?? null) !== '' ? ($cfg['pinned_version'] ?? null) : null,
            (string) ($cfg['repo'] ?? 'https://github.com/metrictower/funnypot-rules')
        );

        if ($this->option('status')) {
            $status = $updater->status();
            $this->line((string) json_encode($status->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            $this->warnIfStale($updater, (int) ($cfg['staleness_alarm_hours'] ?? 0));

            return 0;
        }

        $result = $this->option('rollback')
            ? $updater->rollback($this->option('to') ?: null)
            : $updater->update();

        if ($result->success) {
            $this->info($result->message);
        } else {
            $this->error('[' . $result->status . '] ' . $result->message);
        }

        $this->warnIfStale($updater, (int) ($cfg['staleness_alarm_hours'] ?? 0));

        return $result->success ? 0 : 1;
    }

    private function warnIfStale(RulesUpdater $updater, int $alarmHours): void
    {
        if ($alarmHours <= 0) {
            return;
        }
        $age = $updater->status()->ageSeconds();
        if ($age !== null && $age > $alarmHours * 3600) {
            $this->warn(sprintf(
                'STALE: rules last verified %d hours ago (> %d). The updater may be wedged and the honeypot is going blind.',
                intdiv($age, 3600),
                $alarmHours
            ));
        }
    }
}
