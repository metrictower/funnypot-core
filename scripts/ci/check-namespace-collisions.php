<?php

declare(strict_types=1);

/**
 * Fail the build when two installed funnypot packages define the same class, or when any package
 * claims the bare `Funnypot\` PSR-4 root.
 *
 * The family shares one vendor namespace across many packages. Composer merges PSR-4 prefixes, so
 * two packages declaring the SAME prefix produce one prefix mapped to two directories and the
 * winner is decided by registration order — silently, and differently depending on whether a
 * package is the root or a dependency. The rule that makes that impossible is: every package
 * declares its own distinct sub-namespace, and nobody declares `Funnypot\` bare.
 *
 * This once caught six duplicated FQCNs between funnypot-core and funnypot-laravel, both of which
 * declared the bare root. It works because a longer PSR-4 prefix always wins over a shorter one,
 * so distinct sub-namespaces resolve deterministically.
 *
 * Usage: php scripts/ci/check-namespace-collisions.php [rootDir]
 * Exit 0 clean, 1 on any violation.
 */

$root = $argv[1] ?? getcwd();

/** @return array<string,string> package name => absolute src dir */
function packageSources(string $root): array
{
    $out = [];

    $self = $root . '/composer.json';
    if (is_file($self)) {
        $j = json_decode((string) file_get_contents($self), true);
        if (is_array($j) && isset($j['name'])) {
            $out[$j['name']] = $root;
        }
    }

    foreach (glob($root . '/vendor/metrictower/*', GLOB_ONLYDIR) ?: [] as $dir) {
        $j = json_decode((string) @file_get_contents($dir . '/composer.json'), true);
        if (is_array($j) && isset($j['name'])) {
            $out[$j['name']] = $dir;
        }
    }

    return $out;
}

$packages = packageSources($root);
$violations = [];
$owners = [];

foreach ($packages as $pkg => $dir) {
    $composer = json_decode((string) @file_get_contents($dir . '/composer.json'), true);
    $psr4 = $composer['autoload']['psr-4'] ?? [];

    foreach ($psr4 as $prefix => $_) {
        if (rtrim($prefix, '\\') === 'Funnypot') {
            $violations[] = sprintf(
                '%s declares the bare "Funnypot\\" PSR-4 root. Give it its own sub-namespace.',
                $pkg
            );
        }
    }

    $srcDirs = array_filter(array_map(
        static fn ($p) => $dir . '/' . trim((string) $p, '/'),
        array_values($psr4)
    ), 'is_dir');

    foreach ($srcDirs as $src) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $code = (string) file_get_contents($file->getPathname());
            if (!preg_match('/^namespace\s+([^;]+);/m', $code, $ns)) {
                continue;
            }
            preg_match_all('/^\s*(?:final\s+|abstract\s+)?(?:class|interface|trait|enum)\s+(\w+)/m', $code, $cls);
            foreach ($cls[1] as $name) {
                $owners[trim($ns[1]) . '\\' . $name][$pkg] = true;
            }
        }
    }
}

foreach ($owners as $fqcn => $pkgs) {
    if (count($pkgs) > 1) {
        $violations[] = sprintf('%s is defined by: %s', $fqcn, implode(', ', array_keys($pkgs)));
    }
}

printf("scanned %d package(s), %d class(es)\n", count($packages), count($owners));

if ($violations !== []) {
    fwrite(STDERR, "\nNamespace collisions:\n");
    foreach ($violations as $v) {
        fwrite(STDERR, '  - ' . $v . "\n");
    }
    exit(1);
}

echo "no collisions\n";
exit(0);
