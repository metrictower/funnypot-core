# funnypot-core · B (report-to-mainnet) — implementation plan

**Status:** ready to build · **Date:** 2026-08-19 · **Piece:** B of the funnypot-mainnet program
**Implements:** [`2026-08-19-mainnet-reporting-design.md`](./2026-08-19-mainnet-reporting-design.md) (the design is the source of truth; this plan does not redesign it)
**Anchor service (A1):** [`funnypot-mainnet/docs/2026-08-19-mainnet-api-design.md`](../../funnypot-mainnet/docs/2026-08-19-mainnet-api-design.md) · **Wire shape:** [`abuseipdb-v2-parity-reference.md`](../../funnypot-mainnet/docs/abuseipdb-v2-parity-reference.md)

A builder should be able to execute this top to bottom without re-reading the design. Each phase is
TDD: the test is written and shown to fail first, then the code makes it pass, then the whole suite is
run green before the next phase starts.

> **Relocation (program decision F, 2026-08-19).** The reporter + its queue/transport classes are
> **authored in the new standalone package `metrictower/mainnet-client`** (`Funnypot\Mainnet\`,
> PHP >= 7.3), not in `funnypot-core/src/Report/`. **Phases 1–7 below relocate to that package** (F
> builds them; they are retargeted from `funnypot-core/src/Report/` to the package `src/`).
> **`funnypot-core` `require`s and re-exports the package.** **B's active phases are Phase 8 (app +
> core wiring) and Phase 9 (live integration)** — AppConfig, `demo/*`, `entrypoint.sh`, and the
> `composer` require/update against the re-exported `Funnypot\Mainnet\Reporter`. This **supersedes
> D9** ("fold `src/Report/` into piece C"): the code is no longer in core, so the package carries its
> own 7.3 CI. Decisions D1/D2/D3/D6/D7 are unchanged and now describe the F Reporter.

---

## Orientation

### What exists now (grounding files)

- **The client being ported** — `funnypot/src/App/ThreatIntel/AbuseIpdb.php` (256 lines). This is the
  enqueue→drain reporter with all four guards and the SQLite DDL. Piece B lifts its logic into core.
  - `enqueue()` (lines 65–95): guards in order — no key → no self-IPs → self → not-public → deduped →
    daily-cap → INSERT into `abuse_queue` + mark dedup. Returns `{queued,reason}`.
  - `drain()` (lines 103–156): `SELECT * FROM abuse_queue ORDER BY id LIMIT`, per row 2xx→delete+bumpDaily,
    4xx→delete, else attempts+1 and drop at ≥3. Stops when `dailyCount() >= dailyCap`.
  - `httpPost()` (lines 217–235): the stream-context POST that becomes the fallback transport.
  - `categoriesForProtocol()` (lines 42–57): protocol→category-id CSV, moved verbatim.
  - Storage is inline PDO/SQLite in `db()` (lines 237–255): tables `abuse_reports`, `abuse_daily`,
    `abuse_queue`, WAL mode, `busy_timeout=3000`.
- **The test to mirror** — `funnypot/tests/App/AbuseIpdbTest.php` (151 lines). Uses a temp SQLite file
  and a **recording `callable` sender** (the current `$sender` seam) to prove enqueue guards and drain
  branches with no network. Piece B swaps that seam for the `ReportTransport` fake but keeps every case.
- **The transport model** — `funnypot-core/src/Rules/CurlFetcher.php`. Core's existing ext-curl client
  (SSL verify on, explicit timeouts, `curl_getinfo` status). `CurlReportTransport` mirrors it, GET→POST.
- **Core has no PDO today** — `funnypot-core/src/Store/` is a pure PHP-array store. This is *why* the
  design abstracts storage behind `ReportQueue`: `PdoSqliteReportQueue` is the only PDO in core and stays
  behind an interface so D/E bind their own (wpdb / Eloquent). Guard its tests with `pdo_sqlite`.
- **App wiring points** — `funnypot/demo/index.php` (builds `$abuse`, line 65; wires controller, line 98),
  `funnypot/src/App/Http/HoneypotController.php::maybeReport()` (line 230, enqueues one report per hit),
  `funnypot/demo/listen.php` (lines 40–53, the `$log` closure enqueues per protocol hit),
  `funnypot/demo/abuse-drain.php` (the drain worker), `funnypot/demo/entrypoint.sh` (line 115, the
  drain timer loop), `funnypot/src/App/Config/AppConfig.php` (lines 39–49 fields, 107–114 `fromEnv`).

### How to run the tests

- **`metrictower/mainnet-client` package** (where Phases 1–7 land, per decision F): from the package
  root, run **`php vendor/bin/phpunit`**. Pure PHPUnit, no DB/container. Reporter/queue/transport tests
  live in the package (autoload `Funnypot\Mainnet\` → `src/`). These phases are F's to land; they are
  listed here as the behavioral contract B wires against.
- **funnypot-core**: `require`s and re-exports the package (`composer require metrictower/mainnet-client`);
  from `funnypot-core/`, run **`php vendor/bin/phpunit`**.
- **funnypot (app)** (where Phases 8–9 land — **B's active work**): from `funnypot/`, run
  **`php vendor/bin/phpunit`**. App tests live under `tests/App/`. The app consumes core from
  `vendor/metrictower/funnypot-core`; pulling the new core (which now depends on the package) requires
  **`composer update metrictower/funnypot-core`** (regenerates `composer.lock`).
- **7.3 compat**: the host runs PHP **8.4** — `php -l` here will NOT catch 7.4+ constructs. The
  **`metrictower/mainnet-client` package carries its own `php:7.3` CI** (decision F — supersedes D9);
  B adds no 7.3 gate. See Phase 7.

### Constants fixed by the design (do not re-derive)

- Namespace `Funnypot\Mainnet\` → the **`metrictower/mainnet-client`** package `src/` (decision F —
  no longer `funnypot-core/src/Report/`; core `require`s and re-exports it). Keep
  `declare(strict_types=1)` (7.3-safe).
- Tables in the **same** `intel.sqlite`, distinct names: `mainnet_queue(id,ip,categories,comment,created_at,attempts)`,
  `mainnet_reports(ip PK,reported_at)`, `mainnet_daily(day PK,n)` — so mainnet and AbuseIPDB dedup/cap
  independently — plus `mainnet_meta(k PK,v)` holding the persisted `sensor_id` (D3).
- Base URL is **injected** as `$baseUrl` (`MAINNET_BASE_URL` — scheme + host only, **no path**); the
  reporter **appends `/v1/report`** itself (D1). Never a hardcoded endpoint constant. Default host is an A1
  open decision; app config uses `https://api.funnypot.<tld>` as placeholder (§Risks).
- Key env is **`MAINNET_KEY`** and is the **sole enable gate** — empty key → reporter inert (D2). No
  `FUNNYPOT_MAINNET_REPORT` toggle.
- Report body is the parity shape `ip, categories, comment, timestamp` **plus `sensor_id`** (the persisted
  per-install UUID, D3), `Key:` header, `application/x-www-form-urlencoded`. **Status-only** branching with
  a **`429` exception (SF-7 / decision N):** a `429` has its Error `code` read (`duplicate_report` vs
  `quota_exhausted`) and its `Retry-After`/`X-RateLimit-Reset` headers read; no other status parses the
  body.
- **Optional S4/T `signals` payload — additive, forward-only.** The report body MAY carry an optional
  `signals` object (JSON) + a signal-weighted `confidence` + a `bad_bot`-class `categories` value. The
  reporter **only forwards** what the caller (funnypot-policy) computed — it never derives or scores them
  (S1 computes in core `classify()`, S3 fuses in funnypot-policy). Absent ⇒ the body is the byte-for-byte
  existing shape. Persisted through the queue as two **nullable** `mainnet_queue` columns (`signals TEXT`,
  `confidence REAL`) so they survive `enqueue → drain`. Adds no status branch and no change to
  dedup/cap/decision-N. The honeypot app forwards **none** until funnypot-policy (M/S) lands.
- **Drain resilience envelope (SF-6 / decision N — the F Reporter's `drain()` contract).** Before the
  first POST, consult the shared decision-N breaker marker and **skip the tick while OPEN**. A tick has a
  **10s wall-clock budget**, **aborts after 3 consecutive transport failures** (writing the marker),
  drops re-queued rows past **max-attempts/max-age**, and is fed by a **hard-capped queue** (oldest
  dropped on `push`). `429 duplicate_report` **drops** (re-queue at most once past its 15-min bucket);
  `429 quota_exhausted` **parks** (trip the breaker, stop the tick). Only the quota + transport classes
  trip the breaker; a duplicate-429 never loops.
- **Report comment carries no self-identifying token** (no honeypot marker / `Host` / probed path, D6);
  the reported source IP defaults to `REMOTE_ADDR`, XFF only behind trusted proxies (D7).
- **PHP 7.3 syntax throughout** the package `src/`: no enums, `match`, constructor promotion, named
  args, nullsafe (`?->`), arrow fns, **typed properties**, `??=`, union types in signatures. **Scalar
  and array *parameter* types ARE 7.3-valid and are kept** — only typed *properties* de-type to
  untyped-prop + docblock (as design §4 shows). The **`metrictower/mainnet-client` package carries its
  own `php:7.3` CI** (decision F — **supersedes D9's "fold `src/Report/` into piece C"**); see Phase 7.

---

## Phases 1–7 — build the `metrictower/mainnet-client` package (RELOCATED to F)

> Per decision F these phases **land in the `metrictower/mainnet-client` package**, not
> `funnypot-core/src/Report/`. They are F's to execute; retained here as the build contract (paths are
> the package `src/`; the class is `Funnypot\Mainnet\Reporter`). **B's own work starts at Phase 8.**

## Phase 1 — Contracts + test doubles (`ReportQueue`, `ReportTransport`)

**Change.** Add the two interfaces from design §4.2/§4.3 in the package `src/`:
`ReportQueue` (`push, take, delete, bumpAttempts, count, recentlyReported, markReported, dailyCount,
bumpDaily, sensorId` — `push` enforces the hard queue cap, dropping the oldest row; `take` rows carry
`id`+`attempts`+`created_at`) and `ReportTransport` (`post($url, array $headers, $body): array{status,
body,headers}` — the return now also carries response `headers` so the drain can read `Retry-After` /
`X-RateLimit-Reset` on `429`, SF-7/N). Add the test doubles under `tests/Report/Support/`:
`InMemoryReportQueue` (array-backed, full contract incl. `sensorId()` — UUID once, cached; and the
`push` hard-cap; the stored row **preserves the optional `signals`/`confidence` keys** when present so
`take()` returns them for the drain, S4/T), `RecordingTransport` (captures posted `$url`/headers/bodies —
so a test can assert the posted body carries or omits `signals`/`confidence` — returns a configurable
status **plus a configurable body + headers** so a `429` `code` and `Retry-After` can be simulated — the
successor to the current `recorder()` closure in `AbuseIpdbTest`), a `FakeClock` (advanceable, for the
drain wall-clock budget), and an `ArrayBreakerStore` fake standing in for F's persistent-cache marker
(the decision-N `mnc:breaker` record the drain reads/writes).

**Test first.** `tests/Report/ContractsSmokeTest.php`: assert `InMemoryReportQueue` and
`RecordingTransport` are instances of their interfaces, a round-trip through the in-memory queue
(`push` then `take` then `delete` then `count === 0`) behaves, and `sensorId()` returns a non-empty string
that is **stable across two calls** on the same queue. This fails to load until the interfaces and doubles
exist.

**Verify green.** `php vendor/bin/phpunit tests/Report/ContractsSmokeTest.php`

**Done when.** Interfaces + doubles autoload; smoke test green (incl. stable `sensorId()`); full
`php vendor/bin/phpunit` still green.

---

## Phase 2 — `Reporter::enqueue()` guards

**Change.** Add the package's `src/Reporter.php` with the constructor from design §4.1
(`ReportQueue, ReportTransport, string $baseUrl, string $apiKey, array $selfIps = [], int $dailyCap = 1000,
int $dedupHours = 24` — scalar/array param types are 7.3-valid and kept; assign to **untyped props**) and
`enqueue(string $ip, string $comment, string $categories = '21', array $signals = [], float $confidence = 0.0)`
(the two trailing params are the optional S4/T additive payload — 7.3-valid array/float param types with
defaults, so 2-/3-arg call sites are unchanged). Store `$baseUrl` as-is; the drain
appends `/v1/report`. Port the guard ladder verbatim from
`AbuseIpdb::enqueue` (same order, same reason strings): `no api key` → `self ips not configured` → `self`
→ `not a public ip` → `deduped` → `daily cap` → push + `markReported`. When they pass the guards, the
pushed row carries the optional `signals` (json_encode when non-empty; else omit) and `confidence` (omit
when `0.0`) alongside `ip/categories/comment/created_at` — the reporter **forwards** them and never
inspects them. Storage calls go through
`$this->queue` (`recentlyReported`, `dailyCount`, `push`, `markReported`), not inline PDO. Keep
`reportable()` (the `FILTER_FLAG_NO_PRIV_RANGE | NO_RES_RANGE` check) as a private static. `drain()` can
be a stub returning zeros this phase.

**Test first.** `tests/Report/ReporterTest.php` — port the enqueue cases from `AbuseIpdbTest`
against `InMemoryReportQueue`:
- `test_inert_without_self_ips` → reason `self ips not configured`, count 0.
- `test_no_key` (endpoint set, key `''`) → reason `no api key`.
- `test_never_enqueues_self` → reason `self`.
- `test_skips_private_and_invalid` → `192.168.1.5`, `10.0.0.1`, `127.0.0.1`, `not-an-ip` all `queued=false`.
- `test_dedup_one_report_per_window` → second/third enqueue of same IP → `deduped`, count 1.
- `test_daily_cap_blocks_enqueue` → with cap already at limit (seed `bumpDaily`), enqueue → `daily cap`.
- `test_enqueue_queues_row` → happy path returns `queued=true`, `queueCount()===1`, nothing posted yet.
- `test_enqueue_persists_signals` (S4/T) → `enqueue($ip,$comment,'bad_bot',['ua_class'=>'script',
  'missing_accept_language'=>true],0.8)` → the pushed row carries `signals` (the array/JSON) +
  `confidence=0.8` + `categories='bad_bot'`; a plain `enqueue($ip,$comment)` pushes a row with **no**
  `signals`/`confidence` keys (additive-default preserved).

**Verify green.** `php vendor/bin/phpunit tests/Report/ReporterTest.php`

**Done when.** All enqueue cases green; full suite green. (Guard semantics now match AbuseIpdb 1:1.)

---

## Phase 3 — `Reporter::drain()` status branches

**Change.** Implement `drain(int $limit = 200)` and `queueCount()`. Port `AbuseIpdb::drain` logic through
the queue + transport seams, then wrap it in the decision-N / SF-6 resilience envelope. Build the endpoint
as `rtrim($this->baseUrl,'/').'/v1/report'` (the reporter appends the path — D1).

*Before the loop (decision N):* read the shared breaker marker; if OPEN, **return `{sent:0,failed:0,
pending:queueCount()}` immediately** with no transport call. Start a **10s wall-clock budget** (inject a
`Clock` so it is testable, not a real sleep) and a `consecutiveTransportFails = 0` counter.

*Per row:* stop if `dailyCount() >= dailyCap` or the budget is spent; **drop rows past max-attempts or
max-age**; else POST via `$this->transport->post($endpoint, ['Key: '.$apiKey, 'Accept: application/json'],
http_build_query(['ip','categories','comment','timestamp'=>gmdate('c'),'sensor_id'=>$this->queue->sensorId()]))`.
When the row carries them (S4/T), fold `'signals'=>$row['signals']` (the JSON string) and
`'confidence'=>$row['confidence']` into that body before `http_build_query`; a row without them posts the
unchanged field set. The drain forwards these verbatim and inspects neither — no status branch changes.
Status branches:
- **2xx** → `delete` + `bumpDaily` + sent++; reset `consecutiveTransportFails`.
- **`429`** → read the Error `code` from the body (SF-7): `duplicate_report` → `delete` (re-`push` once
  only if the row's 15-min bucket already elapsed), failed++, **not a fault** (breaker untouched);
  `quota_exhausted` → **park**: leave the row queued, write the decision-N marker OPEN with `until` from
  `Retry-After`/`X-RateLimit-Reset`, **break out of the loop** (breaker owned by F; B's drain honors/writes
  it).
- **other 4xx** → `delete` + failed++ (permanent).
- **5xx / transport failure (status 0)** → `bumpAttempts`, drop at ≥ max-attempts, failed++; increment
  `consecutiveTransportFails` — at **3**, write the decision-N marker (transport class) and **abort the
  tick**.
Return `{sent,failed,pending}` with `pending = queueCount()`. (The breaker record shape + threshold/
cooldown numbers are F's; B's drain only reads OPEN and writes the transport-abort + quota-park markers.)
The marker store + clock are **defaulted seams** (system clock; `sys_get_temp_dir()` filemtime marker
when no persistent cache is injected, N1), so Phase 8's 7-arg `new Reporter(...)` is unchanged — only
the tests inject the `FakeClock` + `ArrayBreakerStore`.

**Test first.** Extend `ReporterTest` with the drain cases, using `RecordingTransport` (extended to return
a body + headers) and an injected fake `Clock` + breaker store:
- `test_enqueue_then_drain_posts_parity_body` → drain sends 1, queue empties, recorded body has
  `ip`, `categories`, **and `sensor_id`** (matching `queue->sensorId()`), and posts to
  `$baseUrl.'/v1/report'` (assert the exact URL the transport saw — the reporter appended the path).
  Assert the body has **no** `signals`/`confidence` keys for a plain enqueue (additive default unchanged).
- `test_drain_forwards_signals` (S4/T) → enqueue with `signals`/`confidence` + a `bad_bot` category,
  drain → the recorded body carries `signals` (the JSON string), `confidence`, and `categories='bad_bot'`
  alongside the parity fields + `sensor_id`; sent=1, queue empties. Assert dedup/cap/decision-N branches
  are identical to the no-signals path (forwarding changes nothing but the body).
- `test_daily_cap_stops_the_drain` → cap 2, three IPs → `sent=2`, `pending=1`, two posts recorded.
- `test_drain_drops_4xx` → transport returns 422 → row deleted immediately, count 0.
- `test_drain_drops_duplicate_429` → transport returns `429 code=duplicate_report` → row **dropped**
  (count 0), breaker **not** tripped, no re-queue loop.
- `test_drain_parks_quota_429` → transport returns `429 code=quota_exhausted` with `Retry-After` → row
  **stays queued**, the tick stops, the shared marker is written OPEN with `until` from the header.
- `test_drain_skips_while_breaker_open` → with the marker OPEN, drain returns `sent=0` and the transport
  is **never called**.
- `test_drain_aborts_after_3_transport_fails` → transport always returns 500/0 → the tick stops after 3
  posts and writes the marker; rows past max-attempts are dropped.
- `test_drain_budget_stops_tick` → with a fake clock advanced past 10s mid-loop, the tick stops early
  (deterministic, no real sleep).
- `test_push_hard_cap_drops_oldest` → pushing beyond the cap drops the oldest row (count == cap).

**Verify green.** `php vendor/bin/phpunit tests/Report/ReporterTest.php`

**Done when.** Drain branch parity + the SF-6/SF-7/N resilience envelope proven with no network; full
suite green.

---

## Phase 4 — `categoriesForProtocol()` moved verbatim

**Change.** Add `public static function categoriesForProtocol($protocol)` to `Reporter`, body copied
exactly from `AbuseIpdb::categoriesForProtocol` (ssh `18,22`, telnet `18,23`, ftp/smtp/pop3/imap `18`,
default `14,15`). Rewrite the `switch` to stay 7.3-safe (a `switch` already is; do not convert to `match`).

**Test first.** `test_categories_for_protocol` in `ReporterTest`, asserting the four cases exactly as
`AbuseIpdbTest::test_categories_for_protocol` does (`ssh→18,22`, `telnet→18,23`, `ftp→18`, `redis→14,15`).

**Verify green.** `php vendor/bin/phpunit tests/Report/ReporterTest.php`

**Done when.** Static mapping green; full suite green. `Reporter` is now feature-complete against
in-memory doubles.

---

## Phase 5 — `PdoSqliteReportQueue` (the real store, `mainnet_*` tables)

**Change.** Add the package's `src/PdoSqliteReportQueue.php` implementing `ReportQueue` against a SQLite file
(constructor takes the db path, lazy `db()` mirroring `AbuseIpdb::db()`: WAL, `busy_timeout=3000`,
`CREATE TABLE IF NOT EXISTS` for `mainnet_queue` (**with two nullable additive columns `signals TEXT`,
`confidence REAL`** for the S4/T payload), `mainnet_reports`, `mainnet_daily` — otherwise identical DDL to
the `abuse_*` trio, distinct names — **plus `mainnet_meta(k TEXT PRIMARY KEY, v TEXT)`**). Map each contract
method to the SQL currently inline in `AbuseIpdb` (`recentlyReported`→SELECT `mainnet_reports`,
`markReported`→INSERT OR REPLACE, `dailyCount`→SELECT `mainnet_daily`, `bumpDaily`→INSERT…ON CONFLICT,
`push`→INSERT `mainnet_queue` (writing `signals`/`confidence` when the row carries them, else `NULL`)
**then enforce the hard cap** (SF-6: `DELETE FROM mainnet_queue WHERE id
NOT IN (SELECT id ... ORDER BY id DESC LIMIT $maxQueue)`, dropping the oldest so an outage cannot grow the
table unbounded), `take`→SELECT ORDER BY id LIMIT (rows carry `created_at` for max-age **and
`signals`/`confidence` so the drain can forward them**), `delete`, `bumpAttempts`→UPDATE attempts,
`count`→COUNT). Implement **`sensorId()`** (D3): SELECT `mainnet_meta` where `k='sensor_id'`; if absent,
generate a v4-style UUID from `random_bytes(16)` (7.3-available — **never** a hardware/MAC id),
`INSERT OR IGNORE` it, and return it; return the same value thereafter. 7.3-safe (no typed props; `?PDO`
property is 7.4+ syntax — use untyped `$db` with a docblock).

**Test first.** `tests/Report/PdoSqliteReportQueueTest.php` (skip if `!extension_loaded('pdo_sqlite')`,
temp-file setUp/tearDown pattern copied from `AbuseIpdbTest`):
- `test_push_take_delete_roundtrip` → push two rows, `take(10)` oldest-first with `id`+`attempts`, delete one, `count()===1`.
- `test_push_take_signals_roundtrip` (S4/T) → a row pushed **with** `signals` (JSON) + `confidence` reads
  back through `take()` with those values intact; a row pushed **without** them reads back `NULL`/absent —
  proving the additive columns are backward-compatible.
- `test_bump_attempts_persists` → `bumpAttempts`, re-`take`, attempts reflected.
- `test_dedup_and_daily_bookkeeping` → `markReported` then `recentlyReported($ip,24)===true`; a fresh IP false; `bumpDaily` twice → `dailyCount()===2`; `recentlyReported` respects the hours window.
- `test_sensor_id_stable_and_persisted` → `sensorId()` returns a non-empty UUID; a second call returns the same; a **fresh `PdoSqliteReportQueue` over the same file** returns the same value (persisted in `mainnet_meta`, not regenerated).
- `test_push_enforces_hard_cap` (SF-6) → with a small cap, pushing beyond it leaves exactly `$maxQueue` rows and the **oldest** are gone (`count()===$maxQueue`, lowest ids dropped).
- `test_mainnet_tables_independent_of_abuse` → open the same file, create an `AbuseIpdb` (or raw
  `abuse_*` inserts) **and** a `PdoSqliteReportQueue`; a `markReported`/`bumpDaily` on one must not appear
  in the other's tables (assert both `mainnet_*` and `abuse_*` coexist with separate counts).

**Verify green.** `php vendor/bin/phpunit tests/Report/PdoSqliteReportQueueTest.php`

**Done when.** Store round-trips green; table independence proven; full suite green (skips cleanly without
`pdo_sqlite`).

---

## Phase 6 — Real transports: `CurlReportTransport` + `StreamReportTransport`

**Change.** Add the package's `src/CurlReportTransport.php` (ext-curl POST, `application/x-www-form-urlencoded`,
`CURLOPT_POST`+`CURLOPT_POSTFIELDS`, `CURLOPT_TIMEOUT`, `SSL_VERIFYPEER/HOST` on, `CURLOPT_FAILONERROR =>
false` so 4xx/5xx still return a status via `curl_getinfo(...RESPONSE_CODE)`; `CURLOPT_HEADERFUNCTION` (or
`CURLOPT_HEADER` split) to capture response headers — modeled on `CurlFetcher`). Add the package's
`src/StreamReportTransport.php` lifting `AbuseIpdb::httpPost()` verbatim (stream context, `ignore_errors`,
8s timeout, parse `$http_response_header` — which already carries the response headers) as the no-ext-curl
fallback. Both return `{status,body,headers}` (headers lower-cased) so the drain can read the `429`
`Retry-After`/`X-RateLimit-Reset` (SF-7/N), and are 7.3-safe. Neither hardcodes the URL or headers — the
reporter supplies them.

**Test first.** `tests/Report/TransportTest.php` — offline-deterministic only (the core suite takes no
network):
- `test_curl_returns_zero_status_on_unreachable` → `CurlReportTransport->post('https://127.0.0.1:1/x', [...], 'a=b')`
  returns an array with `status` int (0), a string `body`, and a `headers` array, and does **not** throw.
  Skip if `!function_exists('curl_init')`.
- `test_stream_returns_array_shape_on_failure` → `StreamReportTransport->post` at an unreachable URL
  returns `{status:0, body:'', headers:[]}` without throwing (uses `@`/`ignore_errors`, so it is safe).
The happy-path 2xx of these classes is proven end-to-end by the live-swap test (Phase 9), not by a unit
test — this is called out so a reviewer does not expect a mocked-200 here.

**Verify green.** `php vendor/bin/phpunit tests/Report/TransportTest.php`

**Done when.** Transports return the contract shape and never throw on network failure; full suite green.

---

## Phase 7 — PHP 7.3 conformance (the package's own CI — decision F)

**Change.** Under decision F the **`metrictower/mainnet-client` package owns its own 7.3 CI** — this
**supersedes D9's "fold `src/Report/` into piece C's matrix"** (the code is no longer in core). In the
package repo:
1. Keep the package `src/*.php` free of 7.4+ constructs — no enums, `match`, constructor promotion,
   named args, nullsafe, arrow fns, **typed properties**, `??=`, union types. **Scalar/array
   *parameter* types stay** (7.3-valid); only *properties* are de-typed.
2. Stand up a `php:7.3` CI lane in the package that runs the full suite on the 7.3 interpreter, with
   `pdo_sqlite` + `curl` + `sodium` loaded so the extension-conditional tests (Phases 5–6) **run**
   (not skip) there.
3. funnypot-core (piece C) no longer carries `src/Report/` in its matrix; C keeps only its own core
   floor-lowering, and core `require`s the package as a standalone 7.3 dependency.

**Test first.** The package's `php:7.3` CI lane is the gate: the full suite must pass on 7.3. Locally, a
`php:7.3-cli` run of the package suite confirms it.

**Verify.** Package `php:7.3` CI green (full suite on the 7.3 interpreter).

**Done when.** The package suite passes on PHP 7.3 in the package's own CI; funnypot-core `require`s the
7.3 package; **no `src/Report/` remains in core and D9's fold-into-C is retired.**

---

## Phases 8–9 — wire the funnypot app + core to the package (B's active work)

## Phase 8 — App wiring (funnypot)

> Cross-repo: this phase lands in **funnypot**, and needs the core component pushed + pulled first
> (`composer update metrictower/funnypot-core`). Keep the app suite green throughout.

**Change.**
1. **Pull core (which now requires the package):** land Phases 1–7 in `metrictower/mainnet-client` and
   publish it; make `funnypot-core` `require metrictower/mainnet-client` and re-export it, push
   `funnypot-core@main`; then in `funnypot/` run `composer update metrictower/funnypot-core`
   (regenerates `composer.lock`; both repos stay PUBLIC so the anonymous composer install keeps working).
2. **AppConfig** (`src/App/Config/AppConfig.php`): add fields beside the `abuseIpdb*` ones —
   `mainnetBaseUrl: string` ← **`MAINNET_BASE_URL`** (scheme + host only, **no path**; default the
   placeholder host `https://api.funnypot.<tld>`), `mainnetKey: string` ← **`MAINNET_KEY`** (the sole
   enable gate), `mainnetDailyCap`/`mainnetDedupHours` ← `FUNNYPOT_MAINNET_DAILY_CAP`/
   `FUNNYPOT_MAINNET_DEDUP_HOURS` (default 1000/24). **No `mainnetReport`/`FUNNYPOT_MAINNET_REPORT`
   field** — key presence is activation (D2). Reuse `selfIps` and `intelDbPath` — no new self-IP config.
3. **`demo/index.php`:** build `$mainnet` beside `$abuse`, gated on **`mainnetKey !== ''`**, using
   `new Reporter(new PdoSqliteReportQueue($config->intelDbPath), new CurlReportTransport(),
   $config->mainnetBaseUrl, $config->mainnetKey, $config->selfIps, $config->mainnetDailyCap,
   $config->mainnetDedupHours)` (the reporter appends `/v1/report` to the base URL). Pass it to
   `HoneypotController`.
4. **`HoneypotController::maybeReport()`:** enqueue to both reporters (guard each for null); the mainnet
   category for web hits is `'21'`, same as abuse. **Fix the ported comment shape (D6):** the comment must
   carry **no self-identifying token** — strip the honeypot marker string, the honeypot `Host`, and the
   probed URL/path (this is the `HoneypotController.php:241` comment the review flagged). The reported IP
   defaults to **`REMOTE_ADDR`** (the connection peer); consult `X-Forwarded-For` only behind
   operator-configured trusted proxies (D7 — the shared policy D/E mirror). **Signals (S4/T): forward
   none yet.** The honeypot has no policy computing the S signals (that is the M/S workstream), so
   `maybeReport()` calls `enqueue()` with the 3-arg form (no `signals`/`confidence`) and posts the
   unchanged body. The optional params exist so a later funnypot-policy adapter can forward its computed
   S signals + a `bad_bot`-class category without another Reporter change — no app change is needed now.
5. **`demo/listen.php`:** in the `$log` closure, enqueue to `$mainnet` too;
   `Reporter::categoriesForProtocol($protocol)` gives the CSV (identical to the abuse call).
6. **`demo/mainnet-drain.php`:** near-copy of `demo/abuse-drain.php`, no-op unless
   `mainnetKey !== ''`, calls `->drain()`. The drain's decision-N envelope (SF-6/SF-7/N) is inside the
   F Reporter, so the worker needs no extra logic; the app injects no shared cache, so the Reporter uses
   the **`sys_get_temp_dir()` filemtime marker fallback** (N1) — a `429 quota_exhausted` or a 3-in-a-row
   transport abort parks the marker there, and the next cron tick short-circuits while it is OPEN. The
   bounded tick (10s budget) keeps the worker cheap even during a mainnet outage.
7. **`demo/entrypoint.sh`:** add a second timer loop beside the abuse-drain (line 115) running
   `php /app/demo/mainnet-drain.php`, interval `FUNNYPOT_MAINNET_DRAIN_INTERVAL` (default 60s).

**Test first.**
- Extend `tests/App/AppConfigTest.php`: `test_mainnet_env_parsed` (set `MAINNET_BASE_URL`, `MAINNET_KEY`,
  `FUNNYPOT_MAINNET_DAILY_CAP`, `FUNNYPOT_MAINNET_DEDUP_HOURS` → fields populated; `mainnetBaseUrl` defaults
  to the placeholder host when unset and holds **no `/v1/report` path**; empty `MAINNET_KEY` → mainnet
  reporting inert).
- New `tests/App/MainnetWiringTest.php` (or extend an existing controller test): with both reporters wired
  against a temp `intel.sqlite` and a `RecordingTransport`, one qualifying hit enqueues **one** row in
  `mainnet_queue` **and** one in `abuse_queue`, and draining one does not affect the other's queue.
- `test_report_comment_has_no_self_identifying_token` (D6): a comment built by `maybeReport` for a
  qualifying hit contains **no** honeypot marker string, no honeypot `Host`, no probed path.
- `node --check` is not relevant (no JS here).

**Verify green.** From `funnypot/`: `php vendor/bin/phpunit`. Also `php -l demo/mainnet-drain.php` and
`bash -n demo/entrypoint.sh`.

**Done when.** App suite green; both reporters enqueue independently on one hit; the report comment carries
no self-identifying token (D6) and the reported IP uses the `REMOTE_ADDR`/trusted-proxy policy (D7);
`composer.lock` updated. **Repointing at staging/prod is confirmed via B's injected `MAINNET_BASE_URL`**
(the reporter appends `/v1/report`) — the wire body/header shape is swap-compatible, but the repoint is the
injected base URL, not merely editing a URL constant (M13); the private/self-IP→4xx branch is provable only
by raw layer-1 replay (Phase 9 / A1), not this suite.

---

## Phase 9 — Live swap integration (ties to A1 §11)

> Cross-repo, manual/opt-in: needs a running A1 mainnet instance and an `internal`-tier key. This is the
> mirror of A1's own "swap test": the wire body/header shape is swap-compatible, and it proves repointing
> works through B's injected `MAINNET_BASE_URL` (the reporter appends `/v1/report`) end to end (M13).

**Change.** None to product code. Add a documented, network-gated integration procedure (a `@group live`
PHPUnit test skipped unless `FUNNYPOT_MAINNET_LIVE_URL`+`FUNNYPOT_MAINNET_LIVE_KEY` are set, or a short
`docs` runbook): construct `Reporter` with a real `CurlReportTransport` and the local mainnet
**base URL** (`FUNNYPOT_MAINNET_LIVE_URL`, host only — the reporter appends `/v1/report`),
enqueue one reportable IP (a self-guarded test IP), `drain()`, assert `sent === 1` (HTTP 2xx from
`/v1/report`).

**Test first.** The live test itself is the artifact; it skips in normal CI. Prove it by running it against
a local A1 and seeing the row land in mainnet.

**Verify.** With A1 up: `FUNNYPOT_MAINNET_LIVE_URL=… FUNNYPOT_MAINNET_LIVE_KEY=… php vendor/bin/phpunit --group live`.

**Done when.** A report POSTed to a live A1 returns 2xx and appears in mainnet; the test skips cleanly with
no env set (so it never breaks offline CI).

---

## Risks & open decisions

1. **Prod host/domain is not fixed (A1 §12).** `MAINNET_BASE_URL` defaults to the placeholder host
   `https://api.funnypot.<tld>` (host only, no path — the reporter appends `/v1/report`). Before prod
   deploy the real host must be set (env override works regardless). Does not block Phases 1–8.
2. **7.3 conformance is the package's own CI (Phase 7 / decision F).** Host is PHP 8.4, so `php -l`
   here is blind to 7.4+ syntax. The **`metrictower/mainnet-client` package stands up its own `php:7.3`
   lane** (carrying `pdo_sqlite`+`curl`+`sodium` so the conditional tests run there) — this
   **supersedes D9** (no fold into piece C). Risk moves to F: the package's 7.3 lane must exist before
   core `require`s it into a 7.3 deployment.
3. **Dual-report posture is resolved (D2).** Mainnet is the **default destination, key-gated on
   `MAINNET_KEY`**; AbuseIPDB is optional/off-by-default (its own key). Both `abuse_*` and `mainnet_*` drain
   independently; the app may run mainnet-only, AbuseIPDB-only, both, or neither. No open "primary vs
   additive" question remains for Phase 8.
4. **`?PDO` nullable typed property in 7.3.** Typed properties are 7.4+. `PdoSqliteReportQueue` must use an
   **untyped** `$db` prop with a docblock, not `private ?PDO $db` (which the app's AbuseIpdb uses under 8.0).
   Easy to miss when copying; C's 7.3 matrix (Phase 7) catches it. Scalar/array *parameter* types are fine.
5. **Transport happy-path has no unit coverage.** By design the core suite is offline, so 2xx transport
   behavior is only proven in Phase 9 (live). Acceptable and called out so it is not mistaken for a gap.
6. **Cross-repo ordering.** Phases 1–7 (the `metrictower/mainnet-client` package) must be published and
   `funnypot-core` must `require` + re-export it, then pulled (`composer update`), before Phase 8 (app)
   can wire them. Phase 9 needs a live A1. D and E consume `Funnypot\Mainnet\Reporter` only after the
   package + core re-export land.
7. **Drain timer doubling in prod.** Phase 8 adds a second background loop in `entrypoint.sh`. Confirm the
   prod host's resource budget tolerates two 60s drains (both are cheap no-ops when unkeyed).

## Definition of done

- `Funnypot\Mainnet\{ReportQueue, ReportTransport, Reporter, PdoSqliteReportQueue, CurlReportTransport,
  StreamReportTransport}` exist in the **`metrictower/mainnet-client`** package (`src/`), all
  7.3-syntax-clean (delivered by F); `funnypot-core` `require`s and re-exports the package.
- `php vendor/bin/phpunit` green in the **`metrictower/mainnet-client`** package (and green in
  **funnypot-core** with the package required + re-exported), including ported enqueue-guard parity,
  drain status-branch parity (incl. the **`429` branch-on-`code`**: `duplicate_report` drop /
  `quota_exhausted` park), the **SF-6/decision-N drain envelope** (marker-skip, 10s budget, abort after
  3 transport fails, max-attempts/max-age drop, hard queue cap), `categoriesForProtocol`, the `sensor_id`
  generation/persistence, the SQLite queue round-trips, `mainnet_*`/`abuse_*` independence, the
  **optional S4/T `signals`/`confidence` forwarding** (present ⇒ body carries them + a `bad_bot`-class
  category; absent ⇒ unchanged body; nullable `mainnet_queue` columns round-trip), and transport
  failure-shape tests (transport returns `{status,body,headers}`).
- The package `src/` is 7.3-clean (scalar/array param types kept; only properties de-typed) and
  **covered by the package's own `php:7.3` CI** (decision F — **supersedes D9**; no fold into piece C).
- **funnypot** app: AppConfig exposes **`MAINNET_BASE_URL`** (host only, no path, env-overridable, default
  placeholder host) and **`MAINNET_KEY`** (sole enable gate) plus the two `FUNNYPOT_MAINNET_*` cap/dedup
  vars; `index.php`/`listen.php`/`HoneypotController` enqueue to both reporters; the report comment carries
  no self-identifying token (D6) and the reported IP follows the `REMOTE_ADDR`/trusted-proxy policy (D7);
  `demo/mainnet-drain.php` drains on its own `entrypoint.sh` timer; `php vendor/bin/phpunit` green;
  `composer.lock` updated.
- One honeypot hit enqueues exactly one `mainnet_queue` row (and one `abuse_queue` row), and the two drains
  never interfere.
- The live-swap test posts to a running A1 `/v1/report` and gets 2xx (skips cleanly offline).
- No security invariant touched: listeners still never block (enqueue local-only); self-IP guard shared and
  inert-when-empty; fingerprint CI still green (no compiled artifact added); no `require`/RCE surface added.

## Key decisions I made (confirm at review)

1. **Nine phases; Phases 1–7 build the package (F), Phases 8–9 are B's app wiring.** Contracts+doubles
   → enqueue → drain → categories → SQLite store → transports → 7.3 conformance (the package's own CI)
   → app wiring → live swap. Each phase keeps its suite green; all cross-repo/network steps defer to the
   end.
2. **Test doubles (`InMemoryReportQueue`, `RecordingTransport`) land in Phase 1** so Phases 2–4 prove the
   reporter with zero storage/network, mirroring how `AbuseIpdbTest` uses its recording sender today.
3. **Real transports (Phase 6) get only failure-shape unit tests**; their 2xx path is covered by the Phase 9
   live-swap test. I did not invent a local HTTP server in the core suite (it is deliberately offline).
4. **The package owns its 7.3 CI (decision F — supersedes D9).** The relocated `src/` is authored
   7.3-clean and gated by the `metrictower/mainnet-client` package's own `php:7.3` lane — no fold into
   piece C. Phase 7 stands up that lane in the package repo.
5. **Phase 8: mainnet is the default destination, key-gated (D2).** The app keeps AbuseIPDB as an optional,
   off-by-default path and runs `Reporter` as the default, active only when `MAINNET_KEY` is set;
   independent `mainnet_*`/`abuse_*` bookkeeping. No open "additive vs primary" question — resolved.
6. **A second `entrypoint.sh` drain loop** (not reusing the abuse-drain process) — keeps the two destinations'
   drains independent and matches the existing one-worker-per-destination shape.

## Dependencies on other pieces

- **A1 · mainnet-api (hard, runtime):** Phase 9 POSTs to A1's `POST /v1/report` and needs an
  `internal`-tier operator key (A1 §8). B's report shape is fixed by the shared parity reference. A1's swap
  test and B's live-swap test are the same proof from both ends. Prod host/domain (A1 §12) unblocks the
  `MAINNET_BASE_URL` default.
- **C · funnypot-core → PHP 7.3 (related, not blocking):** the package is 7.3 from birth and gated by
  its **own `php:7.3` CI** (decision F — supersedes D9; no fold into C's matrix). C still lowers
  funnypot-core's own floor and core `require`s the 7.3 package; C no longer polices the reporter source.
- **D · honeypot-wordpress (dependent):** reuses `Reporter` with a `wpdb`-backed `ReportQueue`;
  depends on B in core and on C (PHP 7.x hosts). Nothing in D lands here.
- **E · honeypot-laravel (dependent):** reuses `Reporter` with a Laravel `DB`/Eloquent `ReportQueue`;
  depends on B in core, independent of D.
- **funnypot app (this program's consumer):** Phases 8–9 wiring + `composer update metrictower/funnypot-core`
  after Phases 1–7 land in `metrictower/mainnet-client` and `funnypot-core` `require`s + re-exports it.

---

## Review resolutions applied (2026-08-19)

- **D1** — Base URL is injected as `$baseUrl` (`MAINNET_BASE_URL`, host only, **no path**) and the reporter
  **appends `/v1/report`**; key renamed to `MAINNET_KEY`. Updated the Constants block, Phase 2 constructor,
  Phase 3 endpoint build + drain body/test URL assertion, Phase 8 AppConfig/wiring, Phase 9 live-URL note,
  Risks #1, DoD, and Dependencies.
- **D2** — Mainnet is the default destination, **active only when `MAINNET_KEY` is set**; dropped the
  `FUNNYPOT_MAINNET_REPORT`/`mainnetReport` field and gate (now `mainnetKey !== ''` everywhere), and marked
  AbuseIPDB optional/off-by-default: Constants block, Phase 8 (AppConfig/index.php/drain), Phase-8 test,
  Risks #3, key decision #5, DoD.
- **D3** — Added `ReportQueue::sensorId()` (Phase 1 contract + double), the `mainnet_meta(k,v)` table and
  UUID generate/persist in `PdoSqliteReportQueue` (Phase 5 + `test_sensor_id_stable_and_persisted`), and
  `sensor_id` in the drained POST body (Phase 3 + test). Noted client dedup/cap stays per attacker-IP and
  server distinctness is by `source_ip` (A1 owns): Constants block, DoD.
- **D6** — Phase 8 now fixes the ported comment shape so it carries **no self-identifying token** (no
  honeypot marker / `Host` / probed path, `HoneypotController.php:241`), with
  `test_report_comment_has_no_self_identifying_token`; reflected in the Constants block and DoD.
- **D7** — Phase 8 documents the reported source IP defaulting to `REMOTE_ADDR`, XFF only behind trusted
  proxies (shared policy D/E mirror): Constants block, Phase 8, DoD.
- **D9 / Nit** — Rewrote Phase 7: **no B-owned 7.3 gate** (removed `scripts/ci/lint-report-73.sh` /
  `php:7.3` matrix / PHPCompatibility dev-deps); `src/Report/` folds into C's single 7.3 matrix, whose
  container carries `pdo_sqlite`+`curl`+`sodium`. Corrected the 7.3 rules to **keep scalar/array parameter
  types** (only properties de-typed) and typed the Phase 2 constructor params accordingly; updated the
  how-to-run note, Risks #2/#4, key decisions #1/#4, DoD, and Dependencies.
- **M13** — Reworded Phase 8 done-criteria: repointing is confirmed via **B's injected `MAINNET_BASE_URL`**
  (reporter appends `/v1/report`), not "only a base-URL change"; the private/self-IP→4xx branch is provable
  only via raw layer-1 replay (Phase 9 / A1).
- **Nit (429)** — Phase 3 drain now **re-queues on `429`** (no attempts bump, row stays queued) instead of
  permanent-drop, with `test_drain_requeues_429`; reflected in the DoD status-branch list.
  *(Superseded by the SF-7 change below: `test_drain_requeues_429` is replaced by
  `test_drain_drops_duplicate_429` + `test_drain_parks_quota_429`.)*

### F relocation (program decision F, 2026-08-19)

- **Phases 1–7 relocate to `metrictower/mainnet-client`.** The reporter/queue/transport classes are
  built in the new standalone package (`Funnypot\Mainnet\`, `src/`, PHP >= 7.3), not
  `funnypot-core/src/Report/`. Added the relocation banner, a "Phases 1–7 (RELOCATED to F)" section
  header, and retargeted the phase paths (`src/Report/X.php` → the package `src/`) and the namespace/
  class (`Funnypot\Report\MainnetReporter` → `Funnypot\Mainnet\Reporter`) throughout.
- **B's active work is Phases 8–9.** Added a "Phases 8–9 (B's active work)" header; Phase 8 item 1 now
  publishes the package, makes `funnypot-core` `require` + re-export it, then `composer update`s core
  into the app. How-to-run, Risks #6, decisions, and dependencies updated to the new order.
- **Phase 7 + 7.3 posture supersede D9.** The package **carries its own `php:7.3` CI** — D9's "fold
  `src/Report/` into piece C's matrix" is retired (the code left core). Rewrote Phase 7, the Constants
  block, the how-to-run note, Risks #2, decisions #1/#4, the DoD, and the C dependency accordingly.
- **D1/D2/D3/D6/D7 intact.** Base-URL/key, key-gated posture, `sensor_id`, comment de-identification,
  and `REMOTE_ADDR` are unchanged — they now describe the F Reporter that Phase 8 wires.

### Decision N + future-proofing (SF-6, SF-7) (2026-08-19)

Threads the canonical fail-open cooldown (decision **N**, review §5) and its drain-side items into the
`drain()` contract (Phase 3, F-owned) and the app drain worker (Phase 8, B's work). Kept design + plan
mutually consistent with the matching design-doc subsection.

- **SF-6 — bounded drain tick.** Phase 3 `drain()` gains the resilience envelope: **marker-check → skip
  while OPEN** (decision N), a **10s wall-clock budget** (injected `FakeClock`, no real sleep), **abort
  after 3 consecutive transport failures** (writes the shared marker), **max-attempts/max-age** drop on
  re-queued rows, and a **hard queue cap** enforced on `push` (Phase 5 SQL + `InMemoryReportQueue`
  double). New tests: `test_drain_skips_while_breaker_open`, `test_drain_aborts_after_3_transport_fails`,
  `test_drain_budget_stops_tick`, `test_push_hard_cap_drops_oldest` / `test_push_enforces_hard_cap`.
- **SF-7 — `429` branches on the Error `code`, never loops.** Phase 3's old "re-queue every 429"
  (`test_drain_requeues_429`) is replaced by `test_drain_drops_duplicate_429` (`duplicate_report` → drop,
  no loop, breaker untouched) and `test_drain_parks_quota_429` (`quota_exhausted` → park + write the
  marker with `until` from `Retry-After`). Only quota + transport classes trip the breaker.
- **N — read the body/headers on `429`.** The `ReportTransport` return grows a `headers` field (Phase 1
  doubles, Phase 6 real transports) so the drain reads `Retry-After`/`X-RateLimit-Reset`; the
  "status-only, no body parse" constant is amended to a **`429`-only** body/header read (Constants block,
  design §2/§8). Phase 1 adds a `FakeClock` + `ArrayBreakerStore` double for F's marker.
- **App wiring (B).** Phase 8's `demo/mainnet-drain.php` needs no extra logic — the envelope is inside the
  F Reporter; the app injects no shared cache, so the Reporter uses the **`sys_get_temp_dir()` filemtime
  marker fallback** (N1) and the cron tick short-circuits while OPEN.
- **Canonical numbers (decision N):** budget 10s, abort at 3 transport fails, drain limit 200/tick.
  Breaker threshold 5 / 60s cooldown / quota-until cap are F's; B's drain only writes the transport-abort
  + quota-park markers and honors OPEN. DoD updated accordingly.

### S/T signals + telemetry (2026-08-19)

Threads the optional request-shape **`signals`** payload (decisions **S4** and **T5**) into the report
path, kept consistent with the matching design-doc subsection. The reporter only **forwards** what the
policy computed (S1 computes in core `classify()`, S3 fuses in funnypot-policy) — B adds no detection.
The addition is purely additive: absent signals ⇒ the byte-for-byte existing body, and dedup/cap/
decision-N/SF-6/SF-7 are untouched.

- **Phase 2 — `enqueue()` gains the optional payload.** Signature grows `array $signals = []` +
  `float $confidence = 0.0` (7.3-valid param types, defaulted → 2-/3-arg call sites unchanged); the
  pushed row carries them when present (`json_encode` the object; omit when empty/`0.0`), and a
  `bad_bot`-class `categories` may accompany them. New test `test_enqueue_persists_signals` (plus the
  plain-enqueue omission assertion). The reporter never inspects the signals.
- **Phase 3 — `drain()` folds them into the POST body.** `signals` (JSON) + `confidence` are added to
  the body when the row carries them, omitted otherwise. New test `test_drain_forwards_signals`;
  `test_enqueue_then_drain_posts_parity_body` also asserts a plain enqueue posts no `signals`/`confidence`
  keys. No status branch changes.
- **Phase 5 — nullable additive columns.** `mainnet_queue` gains `signals TEXT` + `confidence REAL`
  (NULL for reports without policy signals); `push`/`take` carry them; new test
  `test_push_take_signals_roundtrip`.
- **Phase 1 — doubles.** `InMemoryReportQueue` preserves the row's `signals`/`confidence`;
  `RecordingTransport` lets a test assert the posted body carries or omits them.
- **Phase 8 — app forwards none yet.** `maybeReport()` uses the 3-arg `enqueue()` (no signals) because
  the honeypot has no policy computing the S signals — the M/S workstream will supply a funnypot-policy
  adapter that forwards them + a `bad_bot`-class category with no further Reporter change.
- **Fingerprint-safety.** The `signals` object is request-shape observations only (missing-header flags,
  self-consistency flags, UA class, the **digit-stripped/sorted** header fingerprint, anomaly summary) —
  never a scanner/matcher signature string — so CLAUDE.md invariant #1 holds. Constants block + DoD
  updated. Updated: Constants block, Phases 1/2/3/5/8, DoD.

*Ambiguity note:* D3 does not name the sensor_id store explicitly for core; I persist it via the queue
store (`ReportQueue::sensorId()` → `mainnet_meta` in the same `intel.sqlite`), matching the design's
"local config/state store" intent while keeping core storage-agnostic behind the contract.
