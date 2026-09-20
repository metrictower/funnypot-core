<?php

declare(strict_types=1);

/**
 * Curated catalog of WordPress plugins/themes a mass scanner (WPScan, nuclei-wordfence,
 * Plecost) enumerates by fetching a metadata file and reading a version out of it:
 *   plugin: GET /wp-content/plugins/<slug>/readme.txt  -> (?mi)Stable tag:\s*([0-9.]+)
 *   theme:  GET /wp-content/themes/<slug>/style.css    -> (?mi)Version:\s*([0-9.]+)
 * A "found" result is a 200 whose body carries the slug and a version the CVE's
 * compare_versions() bound accepts. This catalog is the source of truth for the served
 * decoy version, compiled into concrete new_page routes by `funnypot compile-wp`.
 *
 * Each `version` is the real MAXIMUM-VULNERABLE version (the last version the CVE affects,
 * i.e. one below the patched release), re-derived from a primary source and captured with its
 * CVE — never invented. An unverifiable slug is dropped, not guessed. Primary sources, verified
 * 2026-09-20:
 *  - tutor                   <= 3.9.4   CVE-2026-0548  (nuclei-wordfence-cve template; research deep-dive)
 *  - fusion-builder          <  3.6.2   CVE-2022-1386  (Fusion Builder < 3.6.2 unauth SSRF; wpscan/NVD)
 *  - woocommerce             <= 5.5     CVE-2021-32789 (WooCommerce 3.3-5.5 SQLi, patched 5.5.1; Wordfence)
 *  - contact-form-7          <  5.3.2   CVE-2020-35489 (CF7 < 5.3.2 unrestricted file upload; NVD/Wordfence)
 *  - elementor               <= 3.6.2   CVE-2022-1329  (Elementor 3.6.0-3.6.2, patched 3.6.3; Wordfence)
 *  - wpforms-lite            <= 1.9.5   CVE-2025-3794  (WPForms Lite <= 1.9.5 stored XSS, patched 1.9.6)
 *  - wordpress-seo (Yoast)   <= 26.8    CVE-2026-1293  (Yoast SEO <= 26.8 stored XSS, patched 26.9)
 *  - wp-file-manager         <= 6.8     CVE-2020-25213 (File Manager 6.0-6.8 unauth RCE, patched 6.9)
 *  - really-simple-ssl       <= 9.1.1.1 CVE-2024-10924 (9.0.0-9.1.1.1 auth bypass, patched 9.1.2)
 *  - all-in-one-wp-migration <= 7.109   CVE-2026-19949 (AIOWPM <= 7.109 unauth SQLi, patched 7.110)
 *  - bricks (theme)          <= 1.9.6   CVE-2024-25600 (Bricks <= 1.9.6 unauth RCE, patched 1.9.6.1)
 *  - flatsome (theme)        <= 3.17.5  CVE-2023-40555 (Flatsome <= 3.17.5 unauth PHP object injection)
 *
 * `contributor`/`author`/`tags` are plausible readme metadata (a real readme always carries
 * them); only `version` + slug are load-bearing for a scanner match. Nothing here is a scanner
 * matcher signature string, so the served bytes stay fingerprint-safe.
 */

return [
    'plugins' => [
        'tutor' => [
            'title' => 'Tutor LMS',
            'version' => '3.9.4',
            'cve' => 'CVE-2026-0548',
            'contributor' => 'themeum',
            'tags' => 'lms, elearning, course, education, learning management system',
        ],
        'fusion-builder' => [
            'title' => 'Fusion Builder',
            'version' => '3.6.1',
            'cve' => 'CVE-2022-1386',
            'contributor' => 'theme-fusion',
            'tags' => 'page builder, builder, editor, visual editor, avada',
        ],
        'woocommerce' => [
            'title' => 'WooCommerce',
            'version' => '5.5.0',
            'cve' => 'CVE-2021-32789',
            'contributor' => 'automattic',
            'tags' => 'e-commerce, store, sales, shop, cart',
        ],
        'contact-form-7' => [
            'title' => 'Contact Form 7',
            'version' => '5.3.1',
            'cve' => 'CVE-2020-35489',
            'contributor' => 'takayukister',
            'tags' => 'contact, form, contact form, feedback, email',
        ],
        'elementor' => [
            'title' => 'Elementor',
            'version' => '3.6.2',
            'cve' => 'CVE-2022-1329',
            'contributor' => 'elemntor',
            'tags' => 'page builder, editor, landing page, drag-and-drop, website builder',
        ],
        'wpforms-lite' => [
            'title' => 'WPForms Lite',
            'version' => '1.9.5',
            'cve' => 'CVE-2025-3794',
            'contributor' => 'wpforms',
            'tags' => 'contact form, form builder, forms, form, drag and drop',
        ],
        'wordpress-seo' => [
            'title' => 'Yoast SEO',
            'version' => '26.8',
            'cve' => 'CVE-2026-1293',
            'contributor' => 'yoast',
            'tags' => 'seo, xml sitemap, google, schema, meta description',
        ],
        'wp-file-manager' => [
            'title' => 'File Manager',
            'version' => '6.8',
            'cve' => 'CVE-2020-25213',
            'contributor' => 'mndpsingh287',
            'tags' => 'file manager, files, download, upload, media',
        ],
        'really-simple-ssl' => [
            'title' => 'Really Simple SSL',
            'version' => '9.1.1.1',
            'cve' => 'CVE-2024-10924',
            'contributor' => 'rogierlankhorst',
            'tags' => 'ssl, https, security, tls, certificate',
        ],
        'all-in-one-wp-migration' => [
            'title' => 'All-in-One WP Migration',
            'version' => '7.109',
            'cve' => 'CVE-2026-19949',
            'contributor' => 'servmask',
            'tags' => 'migration, backup, restore, clone, export',
        ],
    ],
    'themes' => [
        'bricks' => [
            'title' => 'Bricks',
            'version' => '1.9.6',
            'cve' => 'CVE-2024-25600',
            'author' => 'Bricks',
        ],
        'flatsome' => [
            'title' => 'Flatsome',
            'version' => '3.17.5',
            'cve' => 'CVE-2023-40555',
            'author' => 'UX Themes',
        ],
    ],
];
