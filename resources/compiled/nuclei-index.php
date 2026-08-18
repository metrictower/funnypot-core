<?php

/**
 * COMPILED TEMPLATE INDEX — schema 1.
 *
 * Phase 1: hand-written from 5 real nuclei singleton templates to exercise
 * routing + detect end to end. Phase 2 replaces this file with compiler output.
 *
 * Derived from projectdiscovery/nuclei-templates (MIT, (c) 2025 ProjectDiscovery,
 * Inc.). See resources/UPSTREAM-LICENSE.md.
 *
 * Bundle fields consumed in Phase 1: 't' (template ids), 'pid', 'sev', 'sig'.
 * Respond-mode fields ('s','bw','hw','nf','sz','rx','h') are carried where known
 * so later phases have data, but detect mode ignores them.
 */

declare(strict_types=1);

return [
    'schema' => 1,
    'manifest' => [
        'source' => 'projectdiscovery/nuclei-templates',
        'license' => 'MIT (c) 2025 ProjectDiscovery, Inc.',
        'phase' => 1,
        'hand_written' => true,
        'templates' => 5,
        'routes' => 6,
    ],
    'templates' => [
        'git-config' => [
            'sev' => 'medium',
            'tags' => ['config', 'git', 'exposure', 'vuln'],
            'name' => 'Git Configuration - Detect',
        ],
        'configuration-listing' => [
            'sev' => 'medium',
            'tags' => ['config', 'listing', 'exposure', 'edb', 'vuln'],
            'name' => 'Configuration Directory Listing - Detect',
        ],
        'npm-debug-log' => [
            'sev' => 'low',
            'tags' => ['exposure', 'npm', 'logs', 'debug', 'vuln'],
            'name' => 'NPM Debug Log - Detect',
        ],
        'exposed-svn' => [
            'sev' => 'medium',
            'tags' => ['config', 'exposure', 'svn', 'vuln'],
            'name' => 'SVN Configuration - Detect',
        ],
        'webpack-config' => [
            'sev' => 'info',
            'tags' => ['config', 'exposure', 'vuln'],
            'name' => 'Webpack Configuration File - Detect',
        ],
    ],
    'routes' => [
        'GET /.git/config' => ['b' => [[
            's' => 200,
            'bw' => ['[core]'],
            'nf' => ['<html', '<body'],
            'h' => ['Content-Type' => 'text/plain'],
            'pid' => 'git',
            'sev' => 'medium',
            'sig' => 0,
            't' => ['git-config'],
        ]]],
        'GET /config/' => ['b' => [[
            's' => 200,
            'bw' => ['Index of /config', 'Parent Directory'],
            'h' => ['Content-Type' => 'text/html'],
            'pid' => 'apache-autoindex',
            'sev' => 'medium',
            'sig' => 0,
            't' => ['configuration-listing'],
        ]]],
        'GET /npm-debug.log' => ['b' => [[
            's' => 200,
            'bw' => ['npm ERR!'],
            'h' => ['Content-Type' => 'text/plain'],
            'pid' => 'npm',
            'sev' => 'low',
            'sig' => 0,
            't' => ['npm-debug-log'],
        ]]],
        // Same template, second probe path — both keys route to it.
        'GET /assets/npm-debug.log' => ['b' => [[
            's' => 200,
            'bw' => ['npm ERR!'],
            'h' => ['Content-Type' => 'text/plain'],
            'pid' => 'npm',
            'sev' => 'low',
            'sig' => 0,
            't' => ['npm-debug-log'],
        ]]],
        'GET /.svn/entries' => ['b' => [[
            's' => 200,
            'bw' => ['dir'],
            'h' => ['Content-Type' => 'text/plain'],
            'pid' => 'svn',
            'sev' => 'medium',
            'sig' => 0,
            't' => ['exposed-svn'],
        ]]],
        'GET /webpack.config.js' => ['b' => [[
            's' => 200,
            'bw' => ['module.exports'],
            'h' => ['Content-Type' => 'application/javascript'],
            'pid' => 'webpack',
            'sev' => 'info',
            'sig' => 0,
            't' => ['webpack-config'],
        ]]],
    ],
];
