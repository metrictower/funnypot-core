#!/usr/bin/env bash
#
# check-drift.sh — the zero-drift compiled-artifact law (FP-0263).
#
# Recompiles the in-repo artifacts and fails if the working tree drifts from the committed bytes.
# Used identically by CI (.github/workflows/artifact-law.yml) and by contributors (`composer check`),
# so the two can never disagree about what "clean" means. Run from the package root.
#
# It enforces three things:
#   1. `funnypot build` (the in-repo compile DAG) reproduces every committed artifact byte-for-byte.
#   2. `git status --porcelain` over the artifact + generated-template paths is empty — this catches
#      MODIFIED, UNTRACKED (a brand-new output), and DELETED files, which a plain `git diff` misses.
#   3. The manifest.json sidecar's sha256 actually fingerprints nuclei-index.full.php (the invariant
#      merge-routes now maintains — a gate here makes it law).
#
# On drift it prints what changed and how to fix it, then exits 1.
#
# NOTE on `funnypot build` stderr: compile-emulators emits ~23 exit-0 `warning:` lines about the AI
# owns_path templates' path regexes (an intentional design choice — those rules lean on the runtime
# hasAuthSuccessWitness backstop, see EmulatorCompiler::ownsPathVariantWarnings). They are NOT drift
# and do not fail the build; only a non-zero exit or a dirty tree is drift. Do not misread them.

set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT="$(pwd)"

# Paths the law governs: the compiled artifacts AND the generated template inputs (a stale
# compile-ai regeneration is drift just as much as a stale compiled artifact).
PATHS=(resources/compiled templates/generated templates/attack-ai)

echo "== check-drift: funnypot build =="
# The DAG loads the ~6 MB index twice (merge-routes + build-manifest); give it headroom regardless
# of the caller's php.ini. bin/funnypot also raises the limit itself, this is belt-and-braces.
php -d memory_limit=1G bin/funnypot build

echo "== check-drift: git status --porcelain (artifacts must be clean) =="
STATUS="$(git status --porcelain -- "${PATHS[@]}")"
if [ -n "$STATUS" ]; then
    echo "DRIFT: recompiling changed committed artifacts. The compiled tree is out of date." >&2
    echo "$STATUS" >&2
    echo "--- diffstat ---" >&2
    git diff --stat -- "${PATHS[@]}" >&2 || true
    echo "--- first 100 diff lines ---" >&2
    git diff -- "${PATHS[@]}" | head -100 >&2 || true
    echo "" >&2
    echo "Fix: run \`composer build\` (or \`php bin/funnypot build\`) and commit resources/compiled + templates/generated + templates/attack-ai." >&2
    exit 1
fi
echo "clean."

echo "== check-drift: sha256 integrity (manifest.json fingerprints the index) =="
php -r '
$root = getcwd();
$idx = $root . "/resources/compiled/nuclei-index.full.php";
$mj  = $root . "/resources/compiled/manifest.json";
if (!is_file($idx) || !is_file($mj)) {
    fwrite(STDERR, "integrity: missing index or manifest.json\n");
    exit(1);
}
$m = json_decode((string) file_get_contents($mj), true);
$actual = hash("sha256", (string) file_get_contents($idx));
$claimed = (string) ($m["sha256"] ?? "");
if ($claimed !== $actual) {
    fwrite(STDERR, "DRIFT: manifest.json sha256 ({$claimed}) does not fingerprint nuclei-index.full.php ({$actual}).\n");
    exit(1);
}
$bytes = (int) ($m["artifact_bytes"] ?? -1);
$real = filesize($idx);
if ($bytes !== $real) {
    fwrite(STDERR, "DRIFT: manifest.json artifact_bytes ({$bytes}) != index size ({$real}).\n");
    exit(1);
}
echo "integrity OK (sha256 + artifact_bytes match).\n";
'

echo "== check-drift: PASS (zero drift) =="
