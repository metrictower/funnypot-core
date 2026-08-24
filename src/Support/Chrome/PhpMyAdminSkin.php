<?php
declare(strict_types=1);
namespace Funnypot\Support\Chrome;

use Funnypot\Support\VisualPersona;

/**
 * A hand-authored lookalike of the phpMyAdmin query-results screen: a database/table tree down the
 * left, a top bar naming the server, and a results grid on the right. Structural resemblance only —
 * no upstream phpMyAdmin markup or CSS bytes are reproduced. Both the "server version" banner and
 * every CSS class name are seed-derived (PersonaIdentity::productVersion() / VisualPersona::classPrefix())
 * rather than fixed literals — a byte-identical version banner or a fixed `pma-*` class vocabulary on
 * every deployment would itself be a fleet-wide static tell.
 */
final class PhpMyAdminSkin extends AbstractSkin
{
    /** Default left-tree table vocabulary, used only when the caller supplies no navItems (e.g. an
     *  LLM-driven page that never filled the slot) — a mock-authed render fills navItems with the
     *  real table names it wants to show instead (see PageSlots::trusted()). */
    private const DEFAULT_TABLES = ['users', 'sessions', 'options', 'logs'];

    public function matches(string $path): bool
    {
        // Each token is a whole path segment on its own (unlike WordPress's "wp-" prefix family), so
        // an exact per-segment match is the right anchor — no legitimate phpMyAdmin path buries these
        // as part of a longer segment name.
        return PathSegments::has($path, 'phpmyadmin')
            || PathSegments::has($path, 'pma')
            || PathSegments::has($path, 'PMA');
    }

    public function key(): string
    {
        return 'phpmyadmin';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath, string $path = ''): string
    {
        $p = $persona->classPrefix();
        $company = $this->esc($persona->company());
        $domain = $this->esc($persona->domain());
        $db = $this->esc($this->slug($persona->company()));

        // 'mysql' is the shared product key: a future core-template tier reading the same
        // PersonaIdentity for this deployment gets the identical version string, never a
        // second independently-rolled fake that could disagree with this one.
        $version = $this->esc($persona->identity()->productVersion('mysql'));
        $html = '<div class="' . $p . '-topbar">phpMyAdmin &middot; Server: ' . $domain
            . ' via TCP/IP &middot; Server version: ' . $version . '</div>';

        $html .= '<div class="' . $p . '-shell">';
        $html .= $this->tree($p, $db, $company, $slots->navItems());

        $html .= '<main class="' . $p . '-main">';

        $heading = $slots->heading() !== '' ? $slots->heading() : $slots->appName();
        if ($heading !== '') {
            $html .= '<h1 class="' . $p . '-heading">' . $this->esc($heading) . '</h1>';
        }
        if ($slots->intro() !== '') {
            $html .= '<p class="' . $p . '-intro">' . $this->esc($slots->intro()) . '</p>';
        }
        if ($slots->flash() !== '') {
            $html .= '<div class="' . $p . '-notice">' . $this->esc($slots->flash()) . '</div>';
        }

        $html .= $this->results($p, $slots->tableCols(), $slots->tableRows());

        $html .= '</main>';
        $html .= '</div>';

        return $this->document(
            'phpMyAdmin',
            $this->css($p),
            $html,
            ' lang="en"',
            '<meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        );
    }

    /** Turns a persona company name into a plausible lowercase db-name-shaped literal (display only). */
    private function slug(string $company): string
    {
        $slug = strtolower((string) preg_replace('/[^a-z0-9]+/i', '_', trim($company)));
        $slug = trim($slug, '_');
        return $slug !== '' ? $slug : 'app_db';
    }

    /**
     * The left-hand database/table tree. $tables is slot-driven (PageSlots::navItems()) so a
     * mock-authed render can fill it with real table names (e.g. from FakeRecords) instead of the
     * fixed default vocabulary an unfilled LLM page falls back to. Table names are escaped here since,
     * unlike $db/$company (already escaped by the caller), they may originate from a PageSlots slot.
     *
     * @param list<string> $tables
     */
    private function tree(string $p, string $db, string $company, array $tables): string
    {
        if ($tables === []) {
            $tables = self::DEFAULT_TABLES;
        }
        $html = '<nav class="' . $p . '-tree">';
        $html .= '<div class="' . $p . '-tree-title">' . $company . '</div>';
        $html .= '<ul>';
        foreach ([$db, 'information_schema', 'performance_schema', 'mysql'] as $dbName) {
            $html .= '<li class="' . $p . '-db">' . $dbName;
            if ($dbName === $db) {
                $html .= '<ul class="' . $p . '-tables">';
                foreach ($tables as $table) {
                    $html .= '<li class="' . $p . '-table">' . $this->esc($table) . '</li>';
                }
                $html .= '</ul>';
            }
            $html .= '</li>';
        }
        $html .= '</ul></nav>';
        return $html;
    }

    /**
     * @param list<string> $cols
     * @param list<list<string>> $rows
     */
    private function results(string $p, array $cols, array $rows): string
    {
        if ($cols === [] && $rows === []) {
            return '';
        }
        $html = '<div class="' . $p . '-results-info">Showing rows 0 - ' . count($rows) . '</div>';
        $html .= $this->tableHtml($cols, $rows, ' class="' . $p . '-results"');
        return $html;
    }

    private function css(string $p): string
    {
        // Palette reads as a phpMyAdmin-style grey/teal admin scheme, nudged off the product's exact
        // brand hex tokens — resemblance, not reuse.
        return 'body{margin:0;font-family:sans-serif;background:#f4f5f6;color:#2b2f33}'
            . ".{$p}-topbar{background:#2c3a42;color:#cfe3e0;padding:8px 16px;font-size:.85em}"
            . ".{$p}-shell{display:flex;min-height:100vh}"
            . ".{$p}-tree{width:220px;background:#e7ebec;border-right:1px solid #ccd2d4;padding:12px;"
            . 'box-sizing:border-box;font-size:.9em}'
            . ".{$p}-tree-title{font-weight:bold;margin-bottom:8px;color:#356b64}"
            . ".{$p}-tree ul{list-style:none;margin:0;padding-left:6px}"
            . ".{$p}-db{margin:4px 0;color:#2b2f33}"
            . ".{$p}-tables{padding-left:14px;margin-top:4px}"
            . ".{$p}-table{color:#4c5a5f;padding:2px 0}"
            . ".{$p}-main{flex:1;padding:18px 22px}"
            . ".{$p}-heading{margin-top:0;color:#2c3a42}"
            . ".{$p}-intro{color:#5b666b}"
            . ".{$p}-notice{background:#eef6f4;border-left:4px solid #4c9e8f;padding:8px 12px;margin:10px 0}"
            . ".{$p}-results-info{color:#5b666b;font-size:.85em;margin-bottom:6px}"
            . ".{$p}-results{border-collapse:collapse;width:100%}"
            . ".{$p}-results th{background:#dde6e4;text-align:left;padding:6px 10px;border:1px solid #ccd2d4}"
            . ".{$p}-results td{padding:6px 10px;border:1px solid #ccd2d4}";
    }
}
