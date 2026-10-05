<?php

declare(strict_types=1);

/**
 * FP-0436 Phase 1 — CLEAN-ROOM benign corpus for the G1 false-positive gate.
 *
 * Every value is an ORDINARY, non-malicious request value a honeypot would see in a real parameter,
 * body, or header — authored in-repo by generators written for this ticket. It is NOT vendored from
 * libinjection / blazehttp / any upstream FP set (fingerprint-safety golden rule; the FP-0357 corpus
 * is clean-room for the same reason). Values deliberately include the keywords `and`/`or`/`union`/
 * `select`/`;`/`=` in benign contexts (prose, parliamentary "select committee", JSON `union`, field
 * selectors, Accept-Language `;q=`, imperative notes `; update the docs`) so the gate measures a REAL
 * false-positive rate against the shapes that tempt an over-matcher, not a trivially-clean set.
 *
 * Returns a flat list of ['label' => category, 'value' => string]. The deterministic generators give a
 * stable corpus of ~1000+ values (no randomness → reproducible CI measurement).
 *
 * @return array<int,array{label:string,value:string}>
 */
return (static function (): array {
    $out = [];
    $add = static function (string $label, string $value) use (&$out): void {
        $out[] = ['label' => $label, 'value' => $value];
    };

    // 1) Named adversarial-benign shapes the plan/review call out explicitly (must reject).
    $named = [
        'prose:and-or' => 'cats and dogs or small birds',
        'prose:union-drop' => 'union jack flag',
        'json:order-filter' => 'union catalog',
        'api:field-select' => 'select=name,email',
        'header:lang' => 'en-US,en;q=0.9,fr;q=0.8',
        'fpcrs:json-select' => 'select 2024 laptop models',
        'prose:select-committee' => 'trade union select committee hearing',
        'note:update' => '; update the docs before release',
        'note:delete' => 'cleanup; delete later when stable',
        'note:drop' => 'todo; drop it from the agenda',
        'note:insert' => 'reminder; insert here the figures',
        'filter:and' => 'status=1 and type=2',
        'math:and' => '2 and 3 make 5',
        'name:oneill' => "O'Neill",
        'name:dangelo' => "D'Angelo",
        'prose:or' => 'tea or coffee this morning',
    ];
    foreach ($named as $label => $value) {
        $add('named:' . $label, $value);
    }

    // 2) Prose sentences: subject (connective subject)? verb object. Exercises and/or/order intact.
    $subjects = ['the team', 'our users', 'customers', 'the report', 'the committee', 'managers', 'the union', 'students', 'the server', 'the project'];
    $connectives = ['and', 'or', 'but'];
    $verbs = ['reviewed', 'selected', 'ordered', 'updated', 'created', 'dropped', 'deleted', 'inserted', 'joined', 'prepared'];
    $objects = ['the proposal', 'a new plan', 'the quarterly figures', 'their feedback', 'the agenda', 'a backup', 'the dropdown options', 'the final draft', 'two reports', 'the schedule'];
    foreach ($subjects as $si => $s) {
        foreach ($verbs as $vi => $v) {
            $c = $connectives[($si + $vi) % count($connectives)];
            $o = $objects[($si + $vi) % count($objects)];
            $s2 = $subjects[($si + $vi + 3) % count($subjects)];
            $add('prose', "{$s} {$c} {$s2} {$v} {$o}");
        }
    }

    // 3) Product / site search queries.
    $adjs = ['red', 'wireless', 'vintage', 'premium', 'compact', 'refurbished', 'organic', 'stainless', 'ergonomic', 'portable'];
    $nouns = ['laptop', 'headphones', 'coffee maker', 'desk lamp', 'running shoes', 'water bottle', 'office chair', 'phone case', 'backpack', 'monitor stand'];
    $quals = ['under 100', 'with free shipping', 'in stock', 'near me', 'best rated', 'on sale', 'for students', 'reviews', '2024 model', 'black friday'];
    foreach ($adjs as $ai => $a) {
        foreach ($nouns as $ni => $nn) {
            $q = $quals[($ai + $ni) % count($quals)];
            $add('search', "{$a} {$nn} {$q}");
        }
    }

    // 3b) Natural-language questions (interrogatives) — more prose diversity.
    $qwords = ['how do i', 'where can i', 'what is the best', 'why does my', 'when should i', 'who can help with', 'which', 'can you'];
    $topics = ['reset my password', 'order history', 'union membership', 'select a plan', 'update billing', 'delete my account', 'create a report', 'drop a class', 'and/or logic', 'export data'];
    foreach ($qwords as $qi => $qw) {
        foreach ($topics as $ti => $tp) {
            if (($qi + $ti) % 2 === 0) {
                $add('question', "{$qw} {$tp}?");
            }
        }
    }

    // 3c) Second prose pattern: "<subject> <verb> <object> <connective> <object2>".
    foreach ($subjects as $si => $s) {
        $v = $verbs[($si + 2) % count($verbs)];
        $o1 = $objects[$si % count($objects)];
        $o2 = $objects[($si + 4) % count($objects)];
        $c = $connectives[$si % count($connectives)];
        $add('prose2', "{$s} {$v} {$o1} {$c} {$o2}");
        $add('prose2', ucfirst("{$o1} {$c} {$o2} were {$v} by {$s}"));
    }

    // 4) API query-parameter values: sorts, field selectors, filters, pagination, ranges.
    $cols = ['name', 'email', 'created_at', 'price', 'status', 'id', 'updated_at', 'category', 'rating', 'title'];
    foreach ($cols as $ci => $col) {
        $col2 = $cols[($ci + 1) % count($cols)];
        $col3 = $cols[($ci + 2) % count($cols)];
        $add('param:sort', "sort={$col},-{$col2}");
        $add('param:fields', "fields={$col},{$col2},{$col3}");
        $add('param:filter', "filter[{$col}]=active");
        $add('param:order', "order_by={$col}&direction=asc");
        $add('param:select', "select={$col},{$col2}");
        $add('param:range', "{$col}=10..50");
        $add('param:in', "{$col}=1,2,3,4,5");
    }

    // 5) JSON bodies with realistic keys (incl. a `union` type value and a `select` field).
    $jsonTemplates = [
        '{"type":"union","members":42,"active":true}',
        '{"query":"select the best option","page":1}',
        '{"order":{"id":1001,"items":3,"total":"49.99"}}',
        '{"user":{"name":"Jane Doe","role":"admin","verified":false}}',
        '{"filters":["and","or"],"match":"all"}',
        '{"sort":"created_at","dir":"desc","limit":25}',
        '{"event":"update","entity":"profile","changed":["email"]}',
        '{"tags":["sql","nosql","cache"],"count":3}',
        '{"select_all":true,"exclude":[7,8,9]}',
        '{"note":"delete after review; archive first"}',
        '{"address":"12 O\'Brien Street","city":"Cork"}',
        '{"formula":"a = b + c","valid":true}',
    ];
    foreach ($jsonTemplates as $k => $j) {
        $add('json', $j);
        $add('json', str_replace('"', '"', $j) . ' ');
    }

    // 6) HTTP header values.
    $headers = [
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'gzip, deflate, br',
        'en-GB,en;q=0.9,de;q=0.7,fr;q=0.6',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'max-age=3600, must-revalidate',
        'session=abc123; theme=dark; lang=en',
        'application/json; charset=utf-8',
        'bytes=0-1023',
        'no-cache, no-store, must-revalidate',
        'W/"67ab-Jpo+Hdiejdi"',
    ];
    foreach ($headers as $h) {
        $add('header', $h);
    }

    // 7) URLs, paths, redirects.
    $paths = ['/products/category/electronics', '/api/v2/users?page=2&limit=50', '/blog/2024/03/sql-vs-nosql', '/search?q=union+jobs', '/account/settings', '/assets/js/app.min.js', '/docs/getting-started#install', '/cart/checkout', '/images/photo-2024.jpg', '/feed.xml'];
    foreach ($paths as $p) {
        $add('path', $p);
    }

    // 8) Names/addresses with apostrophes, hyphens, accents (quote-handling stress, benign).
    $names = ["O'Brien", "D'Angelo", "Mary-Jane Watson", "Jean-Luc Picard", "José García", "Anne-Marie O'Sullivan", "D'Artagnan", "N'Golo Kanté", "Sinéad O'Connor", "Peter O'Toole"];
    foreach ($names as $nm) {
        $add('name', $nm);
        $add('name', $nm . ', 42 Main Street');
    }

    // 9) Arithmetic / spreadsheet-style benign expressions (no AND/OR-prefixed literal comparison).
    for ($a = 1; $a <= 12; $a++) {
        $b = $a + 3;
        $add('math', "{$a} + {$b} = " . ($a + $b));
        $add('math', "total = {$a} * {$b}");
        $add('math', "price {$a} to {$b}");
    }

    // 10) Free-text comments / notes with punctuation that tempts the stacked production.
    $notes = [
        'Please review and approve; thanks!',
        'Step 1: gather data; step 2: analyze',
        'Note: order matters here, be careful',
        'Draft v2 — update copy, drop the old banner',
        'Create a ticket; assign to the backend team',
        'Select your preferred time; we will confirm',
        'Insert the logo and align it to the left',
        'Delete the temp files after the build finishes',
        'Union meeting rescheduled to Friday at noon',
        'The select few who registered early get access',
    ];
    foreach ($notes as $nt) {
        $add('note', $nt);
    }

    // 11) Misc structured identifiers.
    for ($i = 1; $i <= 120; $i++) {
        $add('uuid', sprintf('%08x-%04x-4%03x-8%03x-%012x', $i * 7, $i, $i, $i, $i * 131));
        $add('email', "user{$i}.name@example-{$i}.com");
        $add('date', sprintf('2024-%02d-%02dT%02d:30:00Z', ($i % 12) + 1, ($i % 28) + 1, $i % 24));
        $add('price', '$' . ($i * 13) . '.99');
        $add('phone', sprintf('+1 (555) %03d-%04d', $i * 3, $i * 97));
    }

    // 12) Code-ish benign fragments (CSS/JS/markdown) that contain SQL-looking words.
    $code = [
        'const rows = table.select(".row");',
        'ORDER BY is a SQL clause explained in chapter 3',
        'if (a && b) { return a || b; }',
        'SELECT dropdown { width: 100%; }',
        'git commit -m "update readme and drop stale docs"',
        'arr.filter(x => x > 1 && x < 10)',
        'UNION and intersection are set operations',
        '# Heading; subheading follows',
        'npm run build && npm test',
        'x = (1 + 2) * 3; // simple math',
    ];
    foreach ($code as $cd) {
        $add('code', $cd);
    }

    return $out;
})();
