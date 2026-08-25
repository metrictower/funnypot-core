<?php
declare(strict_types=1);
namespace Funnypot\Core\Tests\Support\Chrome;

use Funnypot\Core\Support\Chrome\PageSlots;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class PageSlotsTest extends TestCase
{
    public function test_defaults_when_empty(): void
    {
        $s = PageSlots::fromArray([]);
        self::assertSame('', $s->heading());
        self::assertSame([], $s->navItems());
        self::assertSame([], $s->tableRows());
        self::assertFalse($s->hasBody());
    }

    public function test_wrong_types_do_not_throw_and_coerce_to_defaults(): void
    {
        $s = PageSlots::fromArray(['table' => 'none', 'nav_items' => 'x', 'heading' => 42]);
        self::assertSame([], $s->tableRows());
        self::assertSame([], $s->navItems());
        self::assertSame('', $s->heading());
    }

    public function test_caps_are_enforced(): void
    {
        $s = PageSlots::fromArray([
            'nav_items' => ['a', 'b', 'c', 'd', 'e', 'f', 'g'],
            'table' => ['cols' => ['1','2','3','4','5'], 'rows' => [['a'],['b'],['c'],['d']]],
        ]);
        self::assertCount(5, $s->navItems());
        self::assertCount(4, $s->tableCols());
        self::assertCount(3, $s->tableRows());
    }

    public function test_resolve_markers_replaces_markers_across_all_slots(): void
    {
        $persona = VisualPersona::fromSeed(7);
        $s = PageSlots::fromArray([
            'heading' => 'APITOKEN',
            'nav_items' => ['Home', 'EMAIL'],
            'table' => [
                'cols' => ['User', 'APITOKEN'],
                'rows' => [['m.hale', 'AWSKEY']],
            ],
        ]);

        $resolved = $s->resolveMarkers($persona);

        self::assertMatchesRegularExpression('/^tok_[0-9a-f]{12}$/', $resolved->heading());
        self::assertSame('Home', $resolved->navItems()[0], 'non-marker string must pass through unchanged');
        // single (non-row) context: EMAIL is keyed by the slot's own salt ("nav1"), not one fixed
        // persona-wide adminEmail() — see markRows() below for the row-coherent case this fixes.
        self::assertSame($persona->personEmail('nav1'), $resolved->navItems()[1]);
        self::assertSame(['User', 'APITOKEN'], $resolved->tableCols(), 'tableCols (headers) must never be rewritten');
        self::assertSame('m.hale', $resolved->tableRows()[0][0]);
        self::assertSame($persona->awsKey(), $resolved->tableRows()[0][1]);
    }

    public function test_resolve_markers_uses_distinct_salts_so_cells_differ(): void
    {
        $persona = VisualPersona::fromSeed(7);
        $s = PageSlots::fromArray([
            'table' => ['cols' => [], 'rows' => [['APITOKEN', 'APITOKEN'], ['APITOKEN', 'APITOKEN']]],
        ]);

        $resolved = $s->resolveMarkers($persona);
        $tokens = [
            $resolved->tableRows()[0][0],
            $resolved->tableRows()[0][1],
            $resolved->tableRows()[1][0],
            $resolved->tableRows()[1][1],
        ];

        self::assertCount(4, array_unique($tokens), 'distinct cells must resolve to distinct fake tokens');
    }

    /**
     * Regression for the "same email every row" bug: a table row's USERNAME/NAME/EMAIL markers must
     * describe ONE coherent fake person (the email's local-part ties back to that row's person), and
     * different rows must be different people — so EMAIL now varies per row instead of every row
     * repeating one persona-wide adminEmail().
     */
    public function test_markers_are_row_coherent_and_distinct_across_rows(): void
    {
        $persona = VisualPersona::fromSeed(7);
        $s = PageSlots::fromArray([
            'table' => [
                'cols' => ['User', 'Name', 'Email'],
                'rows' => [
                    ['USERNAME', 'NAME', 'EMAIL'],
                    ['USERNAME', 'NAME', 'EMAIL'],
                ],
            ],
        ]);

        $resolved = $s->resolveMarkers($persona);
        [$row0, $row1] = $resolved->tableRows();
        [$userName0, $name0, $email0] = $row0;
        [$userName1, $name1, $email1] = $row1;

        // (a) within each row, USERNAME/NAME/EMAIL describe one coherent person: the email's
        // local-part is exactly that row's userName.
        self::assertStringStartsWith($userName0 . '@', $email0);
        self::assertStringStartsWith($userName1 . '@', $email1);
        self::assertStringContainsString($userName0, $email0);
        self::assertStringContainsString($userName1, $email1);

        // (b) row 0 and row 1 are different people.
        self::assertNotSame($userName0, $userName1);
        self::assertNotSame($name0, $name1);

        // (c) the bug is fixed: EMAIL differs between rows.
        self::assertNotSame($email0, $email1);

        // (d) no literal marker word survives resolution.
        foreach ([$userName0, $name0, $email0, $userName1, $name1, $email1] as $v) {
            self::assertNotSame('NAME', $v);
            self::assertNotSame('EMAIL', $v);
            self::assertNotSame('USERNAME', $v);
        }
    }

    /** New capability: trusted() is for app-supplied data (e.g. real DB rows) — it must bypass
     *  fromArray()'s caps entirely, since a real result set can legitimately be wider than the
     *  5/4/3/4 caps that guard against a runaway model response. */
    public function test_trusted_is_not_length_capped(): void
    {
        $navItems = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
        $tableCols = ['1', '2', '3', '4', '5', '6'];
        $tableRows = [['a'], ['b'], ['c'], ['d'], ['e']];
        $formFields = ['f1', 'f2', 'f3', 'f4', 'f5'];

        $s = PageSlots::trusted('App', 'Title', 'Heading', 'Intro', $navItems, $tableCols, $tableRows, $formFields, 'Flash', 'Footer');

        self::assertSame($navItems, $s->navItems());
        self::assertSame($tableCols, $s->tableCols());
        self::assertSame($tableRows, $s->tableRows());
        self::assertSame($formFields, $s->formFields());
        self::assertCount(8, $s->navItems());
        self::assertCount(6, $s->tableCols());
        self::assertCount(5, $s->tableRows());
        self::assertCount(5, $s->formFields());
    }

    /** trusted() defaults every field so a caller only supplies what it actually has (e.g. just
     *  tableRows for a breached-DB grid). */
    public function test_trusted_defaults_are_empty(): void
    {
        $s = PageSlots::trusted();
        self::assertSame('', $s->appName());
        self::assertSame('', $s->heading());
        self::assertSame([], $s->navItems());
        self::assertSame([], $s->tableRows());
        self::assertFalse($s->hasBody());
    }

    /** trusted() values are real app data, not model placeholders, so a literal MARKERS word must
     *  still resolve if resolveMarkers() is called on it — trusted() itself just skips the caps,
     *  it doesn't change resolveMarkers()'s own behavior (which is unaffected by construction path). */
    public function test_trusted_values_pass_through_resolve_markers_unresolved_when_not_a_marker(): void
    {
        $persona = VisualPersona::fromSeed(11);
        $s = PageSlots::trusted('', '', '', '', [], ['user'], [['m.hale']], [], '', '');
        $resolved = $s->resolveMarkers($persona);
        self::assertSame('m.hale', $resolved->tableRows()[0][0]);
    }
}
