<?php

declare(strict_types=1);

/**
 * FP-0426 — HONEST fire-path benign corpus for the normalization-INDUCED false-positive gate.
 *
 * These are realistic BENIGN param values a catalog/search/filter route (`/catalog/{slug}` and the
 * like) actually receives, deliberately CONCENTRATED on the fire-path shapes that SQL normalization
 * can turn into a tautology/comparison match: free text with `and`/`or`, `like`, `between … and …`,
 * `select`, and `;`. There is NO keyword-free dilution (uuid/email/date padding) — that is exactly how
 * the rejected FP-0436 corpus gamed its gate. If LIKE→= / BETWEEN→= over-induce on natural "X and Y
 * …" search prose, THIS corpus is where it shows, and the gate must surface it honestly.
 *
 * Returns a flat list of ['label' => category, 'value' => string]. Generators are authored in-repo
 * (clean-room), deterministic (no randomness → reproducible).
 *
 * @return array<int,array{label:string,value:string}>
 */
return (static function (): array {
    $out = [];
    $add = static function (string $label, string $value) use (&$out): void {
        $out[] = ['label' => $label, 'value' => $value];
    };

    $nouns = ['shirts', 'shoes', 'mugs', 'laptops', 'books', 'dresses', 'phones', 'chairs', 'lamps', 'bags', 'watches', 'jackets', 'headphones', 'bottles', 'wallets'];
    $nouns2 = ['pants', 'socks', 'cups', 'tablets', 'magazines', 'skirts', 'cases', 'desks', 'bulbs', 'purses', 'bands', 'coats', 'earbuds', 'flasks', 'belts'];

    // 1) "X and/or Y" product searches — the commonest connective shape (must NOT induce).
    foreach ($nouns as $i => $n) {
        $n2 = $nouns2[$i];
        $add('search:and', "{$n} and {$n2} on sale");
        $add('search:or', "{$n} or {$n2} under 50");
        $add('search:and-color', "red {$n} and blue {$n2}");
        $add('search:or-size', "small {$n} or large {$n2}");
    }

    // 2) "X like Y" searches (different words — natural "similar to" phrasing).
    foreach ($nouns as $i => $n) {
        $n2 = $nouns2[$i];
        $add('search:like', "{$n} like these {$n2}");
        $add('search:and-like', "{$n} and something like {$n2}");
    }

    // 3) THE HARD induced cases: repeated word across like / within between after a connective.
    //    "coffee and tea like tea", "X or Y like Y" — unnatural but possible; these are the LIKE→=
    //    tautology-inducers. Kept HONESTLY so the gate counts them.
    foreach (['coffee', 'tea', 'red', 'blue', 'cotton', 'leather', 'steel', 'glass'] as $w) {
        $add('hard:like-repeat', "{$w} and something {$w} like {$w}");
        $add('hard:or-like-repeat', "cheap or premium {$w} like {$w}");
    }

    // 4) "between A and B" price/size ranges, incl. after a connective (BETWEEN→= inducer).
    foreach ($nouns as $i => $n) {
        $n2 = $nouns2[$i];
        $add('range:price', "{$n} priced between 10 and 50 dollars");
        $add('range:conn', "{$n} and {$n2} between 20 and 90");
        $add('range:size', "{$n} size between 8 and 12");
    }

    // 5) filter/param-ish benign values.
    $cols = ['price', 'color', 'size', 'rating', 'brand', 'category', 'stock'];
    foreach ($cols as $i => $c) {
        $c2 = $cols[($i + 1) % count($cols)];
        $add('filter:and', "{$c}=red and {$c2}=large");
        $add('filter:or', "{$c}=1 or {$c2}=2");
        $add('filter:select', "select {$c} and {$c2}");
        $add('filter:between', "{$c} between 1 and 9");
    }

    // 6) prose/notes with SQL words + punctuation (the `;` / select / union shapes).
    $prose = [
        'please sort by name and price ascending',
        'show items in stock or on backorder',
        'the select committee met on tuesday',
        'a union of two sets and their overlap',
        'add to cart; checkout later and pay',
        'filter by brand or category and rating',
        'compare this and that side by side',
        'books about history and the civil union',
        'pick one or the other, not both',
        'between you and me this is a good deal',
        'results like the ones from last week',
        'order status pending and shipped',
        'drop a review and rate the product',
        'update my address and phone number',
        'delete from my wishlist and save later',
        'create a list and share it with friends',
        'insert a coupon and apply the discount',
    ];
    foreach ($prose as $p) {
        $add('prose', $p);
    }

    // 7) catalog slugs (the literal /catalog/{slug} shape — short, hyphenated, benign).
    foreach ($nouns as $i => $n) {
        $add('slug', "{$n}-" . $nouns2[$i] . '-2024');
        $add('slug:brand', "premium-{$n}-collection");
    }

    // 8) a few vetted sql-ish values carried from the existing FalsePositiveReportTest intent
    //    (search phrasings the engine already treats as benign).
    $add('seed:json-select', 'select 2024 laptop models');
    $add('seed:order-by', 'order by date descending please');
    $add('seed:union-jack', 'union jack flag poster');

    return $out;
})();
