# funnypot-core · B (report-to-mainnet) — design spec

**Status:** draft for review · **Date:** 2026-08-19 · **Piece:** B of the funnypot-mainnet program
**Anchor:** [`funnypot-mainnet/docs/2026-08-19-mainnet-api-design.md`](../../funnypot-mainnet/docs/2026-08-19-mainnet-api-design.md) (A1, the service we report to)
**Parity ref:** [`funnypot-mainnet/docs/abuseipdb-v2-parity-reference.md`](../../funnypot-mainnet/docs/abuseipdb-v2-parity-reference.md) (the wire shape both endpoints share)

> **Relocation (program decision F, 2026-08-19).** The reporter and its queue/transport classes are
> **no longer authored in `funnypot-core/src/Report/`**. They live in the new standalone composer
> package **`metrictower/mainnet-client`** (namespace `Funnypot\Mainnet\`, PHP >= 7.3, framework-free)
> as `Funnypot\Mainnet\Reporter` et al. **`funnypot-core` `require`s the package and re-exports it**;
> the WordPress (D) and Laravel (E) extensions get it transitively; non-honeypot consumers depend on
> it directly. **Piece B's scope is now the app + core wiring** (AppConfig, demo entrypoints,
> `entrypoint.sh`, `composer` require/update) against that relocated Reporter — not authoring it. The
> class specs in §3–§4 describe the package's surface B consumes; the behavioral decisions
> D1/D2/D3/D6/D7 still hold and now describe the F Reporter. This **supersedes D9** (see the
> "F relocation" changelog entry below).

---

## 1. What this is

Piece B makes the funnypot honeypot report attacker IPs to **our own** mainnet reputation service
(A1). The reporter reads **`MAINNET_BASE_URL`** (scheme + host only, no path — env-overridable,
default the mainnet placeholder host) and **appends `/v1/report` itself**; the API key is
**`MAINNET_KEY`**. Reporting is **active only when `MAINNET_KEY` is set** — no key → the reporter is
inert (enqueues nothing, sends nothing), the same fail-safe shape as the existing `AbuseIpdb` empty-key
skip. The report body is the *same* AbuseIPDB-compatible shape the app already emits
(`ip,categories,comment,timestamp,sensor_id` + a `Key:` header). The wire body/header shape is
swap-compatible with the existing client, but repointing is done through **B's injected base URL**
(the endpoint is injected, never a hardcoded constant), not by editing a URL constant. The
load-bearing decision, **revised by program decision F**: the reporter is **authored in a new
standalone composer package `metrictower/mainnet-client`** (namespace `Funnypot\Mainnet\`, PHP >= 7.3,
framework-free) as `Funnypot\Mainnet\Reporter`, **not** inside funnypot-core. **funnypot-core
`require`s that package and re-exports it**, so the app **and** the WordPress (D) and Laravel (E)
extensions all reuse one reporter with one set of invariants — self-IP guard, per-IP dedup, daily
cap, and the non-blocking enqueue→drain queue that keeps the single-process protocol listeners from
ever blocking on the network. **Piece B's own scope is therefore to wire the funnypot app + core to
that relocated Reporter** (AppConfig, demo entrypoints, `entrypoint.sh`, the `composer`
require/update), not to author the reporter.

## 2. Scope

> **Scope after decision F.** The reporter, queue, and transport classes below are **authored in the
> `metrictower/mainnet-client` package** (`Funnypot\Mainnet\`), not in `funnypot-core/src/Report/`.
> funnypot-core `require`s and re-exports the package. **B delivers the app + core wiring only**
> (AppConfig, `demo/*`, `entrypoint.sh`, `composer` require/update); the bullets that describe class
> internals now describe the F package's surface B consumes and the behavioral decisions
> (D1/D2/D3/D6/D7) that constrain it.

### v1 (this spec)

- The package component `Funnypot\Mainnet\Reporter` (+ a small supporting surface) that reads a
  base URL (`MAINNET_BASE_URL`, host only), **appends `/v1/report`**, and POSTs the parity shape
  keyed by a `Key:` header (`MAINNET_KEY`). Inert unless the key is set.
- A stable per-install **`sensor_id`**: on first run the reporter generates a UUID and persists it
  to the local state store (via the queue store, **not** a hardware id), then sends it as
  `sensor_id` on every report. It is a convenience label only — mainnet computes sensor distinctness
  server-side from the observed source IP (A1 owns that), so a shared key across many installs still
  yields many distinct sensors.
- The **enqueue → drain** split preserved exactly as in the app's `AbuseIpdb` today: `enqueue()` is a
  fast local write callable from the request path and the listener select-loop; `drain()` does the
  actual HTTP POSTs from a background worker.
- All four guards preserved: self-IP exclusion (inert when self-IPs unknown), public-routable-IP
  check, per-IP dedup window, daily cap.
- A **pluggable queue store** (`ReportQueue` contract) so core carries no storage dependency: the app
  binds a PDO/SQLite implementation (its existing `intel.sqlite`), and D/E bind their own.
- **PHP 7.3 compatibility** from birth — the `metrictower/mainnet-client` package targets 7.3
  independently (so WordPress hosts work), not via piece C's core-floor lowering: no enums, no
  `match`, no constructor promotion, no named args, no nullsafe (`?->`), no arrow functions, no
  **typed properties**, no `??=`. **Scalar and array *parameter* types are 7.3-valid and are kept** —
  only typed *properties* are de-typed to untyped-prop-plus-docblock. curl transport (fallback to
  streams) instead of anything newer. **The package carries its own 7.3 CI** — this **supersedes D9's
  "fold `src/Report/` into piece C's 7.3 matrix"** (the reporter code no longer lives in core, so C
  does not police it; see §6, §7).
- App wiring (**B's actual deliverable**): the honeypot reports to mainnet via the relocated package
  reporter (`Funnypot\Mainnet\Reporter`, reached through core's re-export); base URL env-overridable,
  key the sole enable gate (default destination is mainnet).
- **Optional request-shape `signals` payload (S4/T — additive, reserved).** The report body may carry
  an optional `signals` object, a `bad_bot`-class category, and a signal-weighted `confidence`. The
  reporter **forwards** what the caller (funnypot-policy, per decisions S/T) computed — it never
  computes, scores, or interprets the signals. When no policy supplies them the field is absent and the
  body is byte-for-byte the existing shape, so the addition is purely additive; the honeypot app
  forwards none until the funnypot-policy (M/S) workstream lands. See §4.1, §5, §6.

### Non-goals / fast-follow

- **Removing the app's AbuseIPDB client.** `Funnypot\App\ThreatIntel\AbuseIpdb` stays as an
  **optional, off-by-default** path (its own key; skips when empty). The **shipped default
  destination is mainnet, key-gated on `MAINNET_KEY`** (D2); AbuseIPDB is never the default and no
  piece ever defaults to the AbuseIPDB host. The two run independently — the app may report
  mainnet-only, AbuseIPDB-only, both, or neither (see §3 coexistence). Retiring or fully folding
  AbuseIpdb into the core base is a fast-follow once mainnet is proven in prod.
- **`GET /v1/check` / `GET /v1/blacklist` client.** B only *reports*. The honeypot already treats its
  own blocklist as a separate info-only feed; a mainnet-check client is a later piece.
- **Computing the request-shape signals.** B only *forwards* the `signals` object handed to it (S1
  puts the individual signals in core's `classify()`, S3 the composite in funnypot-policy). The reporter
  neither derives nor weights them; standing up the policy that produces them is the M/S workstream.
- **Bulk report** (`POST /v1/bulk-report`) — reserved in the parity ref, out of v1.
- **A shared reporter-reputation handshake / key rotation protocol** — v1 uses one static operator
  key per deployment (the `internal` tier key from A1 §8).
- **Response-body parsing** (reading back `abuseConfidenceScore`). v1 does **not** parse the success
  body. The **one exception is `429`** (SF-7 / decision N): the drain reads the Error `code`
  (`duplicate_report` vs `quota_exhausted`) to pick the branch, and the `Retry-After` /
  `X-RateLimit-Reset` headers to park the breaker `until`. No other status reads the body.

## 3. Architecture

```
  request path / listener select-loop          background worker (timer)
  (demo/index.php, demo/listen.php,             (demo/mainnet-drain.php,
   HoneypotController::maybeReport)              alongside demo/abuse-drain.php)
        │ enqueue() — local write, never blocks         │ drain() — the HTTP POSTs
        ▼                                                ▼
  ┌───────────────────────────────┐              ┌──────────────────────────────┐
  │ Funnypot\Mainnet\Reporter  (metrictower/mainnet-client, PHP 7.3)            │
  │  guards: self-IP · public-IP · dedup · daily-cap  (enqueue-time)           │
  │  drain: check decision-N marker (skip while OPEN) → budget 10s ·           │
  │         pop rows → POST base+/v1/report → 2xx drop · 429 branch-on-code    │
  │         (dedup→drop · quota→park breaker) · other-4xx drop · 5xx/transport │
  │         retry≤max-attempts, abort tick after 3 consecutive fails           │
  └──────┬──────────────────────────────┬─────────────────────┬───────────────┘
         │ ReportQueue (contract)        │ ReportTransport      │ base URL + Key
         │  (+ sensor_id store)          │                      │
         ▼                               ▼                      ▼
  ┌──────────────────┐        ┌────────────────────┐   MAINNET_BASE_URL  (host only)
  │ PdoSqliteReport   │        │ CurlReportTransport │   MAINNET_KEY
  │ Queue (app: intel │        │ (ext-curl; stream   │        │  reporter appends /v1/report
  │ .sqlite)          │        │  fallback)          │        ▼
  │ WpdbReportQueue(D)│        └────────────────────┘   POST https://api.mainnet.example/v1/report
  │ EloquentQueue (E) │
  └──────────────────┘
```

- **Where it lives:** the **`metrictower/mainnet-client`** package (`Funnypot\Mainnet\`), which
  `funnypot-core` `require`s and re-exports (decision F) — no longer `funnypot-core/src/Report/`. The
  package is plain framework-free PHP with an injected queue + transport, so it stays framework-free
  while D and E supply framework-native queue bindings; non-honeypot consumers depend on it directly,
  without the engine.
- **Where it runs:** the funnypot app process (HTTP request path + protocol listeners enqueue; a cron
  worker drains), and — via D/E — inside WordPress/Laravel request cycles the same way.
- **Transport model mirrors core's existing outbound client** `Funnypot\Rules\CurlFetcher`
  (ext-curl, explicit timeouts, HTTPS-verify on), adapted from GET-fetch to POST-form. The app's
  current stream-context POST (`AbuseIpdb::httpPost`) becomes the fallback transport when ext-curl is
  absent.

## 4. The concrete surface

> **Authored in `metrictower/mainnet-client` (decision F), not core.** The classes below live in the
> package under namespace `Funnypot\Mainnet\` (`Funnypot\Mainnet\Reporter` et al.); `funnypot-core`
> `require`s and re-exports them. They are specified here because B **wires** the app + core to them
> and because decisions D1/D2/D3/D6/D7 constrain their behavior — the authoritative package spec is
> the F / `mainnet-client` design.

Namespace `Funnypot\Mainnet\` in the **`metrictower/mainnet-client`** package. Signatures written for
PHP 7.3: **untyped properties** + docblocks (typed properties are 7.4+), no constructor promotion, no
union return types. **Scalar and array parameter types are 7.3-valid and are kept** (e.g.
`array $selfIps`, `array $headers`) — only *properties* are de-typed, not parameters.

### 4.1 `Reporter`

```php
namespace Funnypot\Mainnet;

final class Reporter
{
    /**
     * @param ReportQueue     $queue      pluggable persistence + sensor_id store (app: PDO/SQLite; WP: wpdb; Laravel: DB)
     * @param ReportTransport $transport  the HTTP POST doer (CurlReportTransport by default)
     * @param string          $baseUrl    MAINNET_BASE_URL — scheme + host only, NO path
     *                                     (e.g. https://api.mainnet.example); the reporter appends /v1/report
     * @param string          $apiKey     MAINNET_KEY, sent as the `Key:` header; empty key → reporter inert
     * @param string[]        $selfIps    our own public IP(s); reporting is inert when empty
     * @param int             $dailyCap
     * @param int             $dedupHours
     */
    public function __construct(
        ReportQueue $queue,
        ReportTransport $transport,
        string $baseUrl,
        string $apiKey,
        array $selfIps = [],
        int $dailyCap = 1000,
        int $dedupHours = 24
    ) { /* assign to untyped props; scalar/array PARAM types are 7.3-valid */ }

    /**
     * Queue a report if it passes the guards. Fast local write; safe from the request path and the
     * listener loop. Guards identical to the app's AbuseIpdb: no key / no self-IPs / self / private
     * IP / deduped / daily-cap all short-circuit.
     *
     * $signals / $confidence are the optional S4/T additive payload: the request-shape `signals` object
     * (missing-header flags, self-consistency flags, UA class, the digit-stripped header fingerprint +
     * local anomaly summary) and the signal-weighted `confidence` the CALLER (funnypot-policy) computed.
     * The reporter only persists+forwards them — it never derives or interprets them. Both default to
     * empty/absent, so existing 2- and 3-arg call sites are unchanged and the guard ladder is untouched.
     * A `bad_bot`-class $categories may accompany them (S4); the reporter forwards whatever category the
     * caller supplies. array/scalar PARAM types are 7.3-valid.
     * @param array<string,mixed> $signals   forwarded verbatim; empty ⇒ omitted from the body (§5)
     * @param float               $confidence signal-weighted; 0.0 ⇒ omitted from the body
     * @return array{queued:bool,reason:string}
     */
    public function enqueue(
        string $ip,
        string $comment,
        string $categories = '21',
        array $signals = [],
        float $confidence = 0.0
    );

    /**
     * Send queued reports to $baseUrl.'/v1/report'. Each POST carries the parity body plus the
     * persisted sensor_id (from the queue store), and — when the queued row carries them (S4/T) — the
     * optional `signals` object and `confidence` field, forwarded verbatim. Rows with no signals post
     * the unchanged body. The drain never inspects or scores the signals; forwarding them changes no
     * status branch, dedup, cap, or the decision-N/SF-6/SF-7 envelope.
     *
     * Decision N (fail-open cooldown): before the first POST, consult the shared breaker marker;
     * if it is OPEN, skip the whole tick and return immediately (zero socket work). Each tick has a
     * wall-clock budget (10s) and aborts after 3 consecutive transport failures, writing the
     * decision-N marker so the next tick short-circuits.
     *
     * Status branches (429 branches on the Error `code`, per SF-7):
     *   2xx                          → drop + bump daily
     *   429 code=duplicate_report    → DROP (the 15-min throttle; resubmitting is pointless — NOT a
     *                                   fault, never re-queued in a loop). Re-queue at most ONCE only
     *                                   if the row's 15-min bucket has already elapsed.
     *   429 code=quota_exhausted     → PARK: stop the tick and trip the decision-N breaker OPEN
     *                                   (quota fault class); rows stay queued for a later tick.
     *   other 4xx                    → drop (permanent — a real client error)
     *   5xx / transport failure      → transport fault class: bump attempts, drop at ≥ max-attempts;
     *                                   3 consecutive transport failures abort the tick + write the
     *                                   decision-N marker.
     * Re-queued rows are also dropped past a max-age; the queue is hard-capped (oldest dropped on
     * push). Stops at the daily cap. Only the quota + transport classes trip the breaker; a
     * duplicate-429 never does.
     * @return array{sent:int,failed:int,pending:int}
     */
    public function drain(int $limit = 200);

    public function queueCount();

    /** Protocol → category-id CSV, moved verbatim from AbuseIpdb::categoriesForProtocol(). */
    public static function categoriesForProtocol(string $protocol);
}
```

The `enqueue`/`drain` bodies are ported from `funnypot/src/App/ThreatIntel/AbuseIpdb.php`
(lines 65–156) with these changes: (1) the endpoint is **injected** — the reporter appends
`/v1/report` to the injected `$baseUrl`, never the constant `https://api.abuseipdb.com/api/v2/report`;
(2) storage goes through `ReportQueue` instead of inline PDO; (3) the POST body gains the persisted
`sensor_id` (from `ReportQueue::sensorId()`); (4) the drain **branches `429` on the Error `code`**
(SF-7): `duplicate_report` drops (never loops; re-queues at most once past its 15-min bucket),
`quota_exhausted` parks per decision N (trip the breaker, stop the tick) — the earlier
"unconditionally re-queue every 429" behaviour is superseded; (5) the drain gains the decision-N /
SF-6 resilience envelope (marker check → skip while OPEN, 10s tick budget, abort after 3 consecutive
transport failures writing the marker, max-attempts/max-age drop, hard queue cap); (6) `enqueue()`
persists the optional `signals`/`confidence` (S4/T) alongside the row and `drain()` folds them into the
POST body when present (empty ⇒ omitted, body unchanged). Otherwise the branch logic (2xx drop /
other-4xx drop / 5xx retry) is unchanged.

The **breaker marker store and the clock are defaulted seams**, not new required constructor args: with
no persistent cache injected the Reporter uses the decision-N `sys_get_temp_dir()` filemtime fallback
(N1), and the clock defaults to system time. So the app's construction (§4.4) stays the same 7-arg
call; tests inject a fake clock + marker store to exercise the budget/breaker deterministically.

### 4.2 `ReportQueue` (contract) — keeps core storage-agnostic

```php
namespace Funnypot\Mainnet;

interface ReportQueue
{
    /**
     * Append one queued report. Enforces the hard queue cap (SF-6): when the queue is at
     * $maxQueue, the oldest row is dropped so the table cannot grow unbounded during an outage.
     * The optional `signals`/`confidence` keys (S4/T) are persisted when present and forwarded at drain;
     * absent for reports carrying no policy signals (backward-compatible).
     * @param array{ip:string,categories:string,comment:string,created_at:string,signals?:string,confidence?:float} $row
     */
    public function push(array $row);
    /** @return array<int,array<string,mixed>>  oldest-first, each with id+attempts+created_at */
    public function take($limit);
    public function delete($id);
    public function bumpAttempts($id, $attempts);
    public function count();
    // dedup + daily-cap bookkeeping (was abuse_reports / abuse_daily):
    public function recentlyReported($ip, $withinHours);
    public function markReported($ip);
    public function dailyCount();
    public function bumpDaily();
    /**
     * Stable per-install id. Generate a UUID on first call and PERSIST it to the local state store
     * (NOT a hardware id), returning the same value on every later call. Sent as `sensor_id`.
     * @return string
     */
    public function sensorId();
}
```

Core ships **`PdoSqliteReportQueue`** implementing this against a SQLite file — the same table DDL
the app already creates (`abuse_queue` / `abuse_reports` / `abuse_daily`), reused so the app's
existing `intel.sqlite` and its `demo/abuse-drain.php` retention keep working. To avoid two IPs being
double-tracked, the mainnet queue uses **its own table names** (`mainnet_queue`, `mainnet_reports`,
`mainnet_daily`) in the same SQLite file so mainnet and AbuseIPDB dedup/cap independently. The
`sensor_id` is persisted in a small **`mainnet_meta(k TEXT PRIMARY KEY, v TEXT)`** row
(`k='sensor_id'`), generated once with a v4-style UUID from `random_bytes(16)` (7.3-available) —
never a hardware/MAC id. `mainnet_queue` carries two **nullable, additive** columns — `signals TEXT`
(the S4/T `signals` object, JSON-encoded) and `confidence REAL` — so a report's forwarded signals
survive `enqueue → drain`; both are `NULL` for reports with no policy signals, keeping the table
backward-compatible.

D (WordPress) binds a `wpdb`-backed queue; E (Laravel) binds a `DB`/Eloquent-backed queue. Neither
pulls PDO/SQLite into core.

### 4.3 `ReportTransport` (contract) + `CurlReportTransport`

```php
namespace Funnypot\Mainnet;

interface ReportTransport
{
    /**
     * @param string[] $headers  e.g. ['Key: …','Accept: application/json']
     * @return array{status:int,body:string,headers:array<string,string>}
     *         `headers` carries response headers (lower-cased keys) so the drain can read
     *         `Retry-After` / `X-RateLimit-Reset` on a `429` to park the breaker (SF-7 / decision N);
     *         `body` carries the Error `code` on `429`. Empty for other statuses.
     */
    public function post($url, array $headers, $body);
}
```

- **`CurlReportTransport`** — ext-curl POST, `application/x-www-form-urlencoded`, `CURLOPT_TIMEOUT`,
  `SSL_VERIFYPEER/HOST` on, `ignore`-errors semantics (return status even on 4xx/5xx). Modeled on
  `Funnypot\Rules\CurlFetcher`.
- **`StreamReportTransport`** — fallback lifting `AbuseIpdb::httpPost()` verbatim (stream context,
  `ignore_errors`, hard timeout, parse `$http_response_header`) for hosts without ext-curl. Both are
  7.3-safe.

### 4.4 App wiring (funnypot)

- **AppConfig** (`funnypot/src/App/Config/AppConfig.php`) gains, alongside the existing
  `abuseIpdb*` fields:
  - `mainnetBaseUrl: string` ← `MAINNET_BASE_URL` (**scheme + host only, NO path**; **default** the
    mainnet placeholder host, e.g. `https://api.funnypot.<tld>`; override for staging/local). The
    reporter appends `/v1/report`.
  - `mainnetKey: string` ← `MAINNET_KEY` — **the sole enable gate**. Empty key → mainnet reporting is
    inert (no `FUNNYPOT_MAINNET_REPORT` toggle; key presence is the switch, mirroring AbuseIpdb).
  - `mainnetDailyCap` / `mainnetDedupHours` ← `FUNNYPOT_MAINNET_DAILY_CAP` /
    `FUNNYPOT_MAINNET_DEDUP_HOURS` (reuse the `internal`-tier high cap from A1 §8; default 1000/24 as
    today). `selfIps` and `intelDbPath` are shared with AbuseIpdb — no new self-IP config.
- **`demo/index.php`** builds a `Reporter` right beside the existing `$abuse` (same
  `$config->selfIps`, a `PdoSqliteReportQueue($config->intelDbPath)`), gated on
  `mainnetKey !== ''`. `HoneypotController::maybeReport()` (line 242) enqueues to both reporters.
- **Signals payload (S4/T) is wired but empty until funnypot-policy lands.** `enqueue()` accepts the
  optional `signals`/`confidence` args; the honeypot app has no policy computing them yet (that is the
  M/S workstream), so `maybeReport()` passes **none** and posts the unchanged body. The parameter path
  is present so a later funnypot-policy adapter can forward its computed S signals + a `bad_bot`-class
  category without another Reporter change.
- **Report comment (D6): no self-identifying token.** The comment passed to `enqueue()` must **not**
  contain the honeypot marker string, the honeypot `Host`, or the probed URL/path. When porting the
  comment shape from the app (`HoneypotController.php:241`), strip these so a leaked comment cannot
  deanonymize the honeypot. See §6.
- **Reported source IP (D7).** The IP handed to `enqueue()` defaults to the connection peer
  (`REMOTE_ADDR`); `X-Forwarded-For` is consulted **only** behind operator-configured trusted proxies.
  This is the **shared policy the D (WordPress) and E (Laravel) reporters mirror**.
- **`demo/listen.php`** does the same in its `$log` closure (line 46–53): one `enqueue()` per hit to
  each configured reporter. `Reporter::categoriesForProtocol()` replaces the AbuseIpdb call.
- **New `demo/mainnet-drain.php`** — a near-copy of `demo/abuse-drain.php`; the entrypoint's timer
  runs both drains. Non-blocking model unchanged.

## 5. Data / config model

- **New env, read by AppConfig:** **`MAINNET_BASE_URL`** (scheme + host only, no path; default the
  mainnet placeholder host, override for staging/local — the reporter appends `/v1/report`),
  **`MAINNET_KEY`** (the sole enable gate — inert when empty), `FUNNYPOT_MAINNET_DAILY_CAP`,
  `FUNNYPOT_MAINNET_DEDUP_HOURS`. Reuses `FUNNYPOT_SELF_IPS` and `FUNNYPOT_INTEL_DB`. There is **no**
  `FUNNYPOT_MAINNET_REPORT` toggle — key presence is activation (D2). `MAINNET_BASE_URL`/`MAINNET_KEY`
  are the program-canonical names (D1), shared by the web-lookup and blacklist pieces.
- **New tables (same SQLite file, created by `PdoSqliteReportQueue`):** `mainnet_queue(id,ip,
  categories,comment,created_at,attempts` **+ nullable `signals TEXT`, `confidence REAL`** (S4/T)`)`,
  `mainnet_reports(ip PK,reported_at)`, `mainnet_daily(day PK,n)` — identical DDL to the `abuse_*` trio
  (bar the two additive `mainnet_queue` columns), distinct names so the two destinations dedup/cap
  independently — plus **`mainnet_meta(k PK,v)`** holding the persisted `sensor_id` (D3).
- **Report body:** parity fields `ip,categories,comment,timestamp` **plus `sensor_id`** (the persisted
  per-install UUID), **plus the optional S4/T additive fields `signals` (JSON object) and `confidence`
  (signal-weighted)** — present only when the caller supplied them, omitted otherwise so the default
  body is unchanged. `categories` may be a `bad_bot`-class value when the policy classifies the source as
  a bad bot. Client dedup/cap remains **per attacker-IP**; mainnet computes sensor distinctness from the
  server-observed `source_ip` (A1 owns that), not from `sensor_id`. Mainnet treats the report-carried
  signals as report evidence (T1); the reporter never scores them.
- **Category ids** are AbuseIPDB's 1–23 (A1 keeps them), so `categoriesForProtocol()` moves over
  unchanged.

## 6. Security & invariants touched

- **Listeners must never block on the network.** Preserved: `enqueue()` is a local write only; all
  HTTP happens in `drain()` on the worker. This is the single most important invariant of the port.
- **A drain tick is bounded even during a total outage (SF-6 / decision N).** A tick (1) short-circuits
  when the shared decision-N breaker marker is OPEN — no socket work at all; (2) carries a 10s
  wall-clock budget; (3) aborts after 3 consecutive transport failures and writes the shared marker so
  the following ticks skip; (4) drops re-queued rows past a max-attempts/max-age; (5) is fed by a
  hard-capped queue (oldest dropped on push). This matters most for D/E, whose drain can run inside a
  loopback WP-Cron / scheduler request — an outage must never serially burn `limit × timeout` seconds
  or grow the queue table unbounded. The app's own cron worker inherits the same envelope.
- **`429` is two different faults and must not loop (SF-7).** The drain branches on the Error `code`:
  `duplicate_report` (the 15-min throttle) drops — re-queued at most once past its bucket, never in a
  loop; `quota_exhausted` parks the breaker per decision N (its `until` from `Retry-After` /
  `X-RateLimit-Reset`). Only the quota + transport classes trip the breaker; a duplicate-429 never
  does. This prevents an exhausted fleet from re-probing a day-long quota window every tick.
- **Self-IP guard.** Ported exactly: inert when `selfIps === []`, and never reports an IP in the
  self set. Shared self-IP config with AbuseIpdb, so the AbuseIPDB self-guard invariant (CLAUDE.md
  security invariant 4) covers mainnet too — test egress can't be reported to either destination.
- **PHP 7.3 constraint (the package owns its own gate).** The whole `Funnypot\Mainnet\` component is
  written to 7.3: no enums/`match`/constructor-promotion/named-args/nullsafe/arrow-fns/**typed-props**/`??=`.
  **Scalar and array *parameter* types stay** (7.3-valid); only typed *properties* are de-typed.
  Transport uses curl or streams. The **`metrictower/mainnet-client` package carries its own 7.3 CI**;
  this **supersedes D9's "fold `src/Report/` into piece C's matrix"** — the code left core, so C no
  longer polices it. Still mandatory because D targets PHP-7.x WordPress hosts and the package is a
  standalone 7.3 dependency of core.
- **Report comment carries no self-identifying token (D6).** The comment must never contain the
  honeypot marker string, the honeypot `Host`, or the probed URL/path. The app-side port of the
  comment shape (`HoneypotController.php:241`) is fixed so no such token is emitted in the first
  place — a leaked comment must not let an attacker fingerprint or locate the honeypot. Mirrors the
  fingerprint-safety invariant (CLAUDE.md #1) on the reporting side.
- **Optional `signals` payload is fingerprint-safe and forwarded, not derived (S4/T).** The `signals`
  object carries request-shape observations only — missing-header booleans, self-consistency flags, a UA
  class, the **digit-stripped/sorted** header fingerprint, and a local anomaly summary — never a
  canonical scanner/matcher signature string (nuclei matcher words, CRS ids/`msg`), so it cannot leak a
  detector signature and stays clear of the fingerprint-safety invariant (CLAUDE.md #1). The reporter
  only persists and forwards what the policy computed (S1 in `classify()`, S3 in funnypot-policy); it
  neither derives nor interprets the signals, so no detection logic — and no signature vocabulary —
  enters the reporter. The field is optional and outbound to our own mainnet, not emitted in the
  honeypot response, so the honeypot response is untouched (invariant 5).
- **Reported source IP defaults to `REMOTE_ADDR` (D7).** The IP that gets reported is derived from
  the connection peer; `X-Forwarded-For` is trusted **only** behind operator-configured trusted
  proxies (untrusted XFF is spoofable → third-party report poisoning). This is the shared policy the
  D (WordPress) and E (Laravel) reporters mirror.
- **`sensor_id` is a label, not a secret (D3).** A random per-install UUID persisted locally (never a
  hardware id). It is spoofable and mainnet does not trust it for distinctness — the server keys
  distinctness on the observed `source_ip`. Client-side dedup/cap remain per attacker-IP.
- **Fingerprint-safety CI stays green.** The gate (`scripts/ci/check-fingerprint-safety.php`) scans
  *compiled attack artifacts* under `resources/compiled/`, not runtime source — the reporter adds no
  compiled artifact and emits no detector signature strings, so it is out of the gate's scope and
  cannot trip it. Category ids (numbers) are not signatures.
- **No new outbound-fetch RCE surface.** Unlike the rules-updater, B only *sends* form fields to a
  configured host and reads back a status code; it never `require`s or executes a response. No
  ed25519/array-literal machinery needed. The endpoint host comes from operator env, not from
  attacker-controlled data.
- **Content-Type / status invariants (honeypot response) untouched** — B never influences what the
  honeypot serves; it is a side-channel report.

## 7. Testing strategy

> **Ownership after decision F.** The class-level unit tests below (port-parity, `sensor_id`, queue
> contract, transport) are authored in the **`metrictower/mainnet-client` package** (F); they remain
> here as the behavioral acceptance criteria the relocated `Funnypot\Mainnet\Reporter` must meet. **B
> owns the app-integration and live-swap tests** that exercise the app + core wiring against the
> re-exported package.

- **Port-parity unit tests (package):** reuse the app's existing `AbuseIpdb` test cases against
  `Reporter` with an injected fake `ReportTransport` — assert enqueue guards (no key / no
  self-IPs / self / private IP / dedup / daily-cap) and the drain status branches (2xx drop+bump,
  **429 `duplicate_report` drop**, **429 `quota_exhausted` park**, other-4xx drop,
  5xx retry-then-drop). Pure PHPUnit, no network (matches core's host-run suite). Assert the POST
  goes to `$baseUrl.'/v1/report'` (the reporter appends the path) and the body carries `sensor_id`.
- **`429`-code branch tests (SF-7):** a transport returning `429` with `code=duplicate_report` →
  the row is **dropped**, no re-queue loop, the breaker does **not** trip; a `429` with
  `code=quota_exhausted` → the tick **parks** (row stays queued, breaker marker written OPEN with an
  `until` derived from a stubbed `Retry-After`); a subsequent tick with the marker OPEN **skips**
  with zero transport calls.
- **Drain-resilience tests (SF-6 / decision N):** with a fake transport that always fails
  (timeout/5xx), a drain tick **aborts after 3 consecutive transport failures** and writes the shared
  marker; a tick started with the marker OPEN returns immediately with `sent=0` and no transport
  call; the wall-clock budget stops a tick (inject a clock so the budget is deterministic, not a real
  sleep); re-queued rows past max-attempts/max-age are dropped; `push` beyond the hard cap drops the
  oldest row.
- **`sensor_id` tests:** first `sensorId()` generates a UUID and persists it; a second call and a
  fresh instance over the same store return the **same** value; the drained body includes it.
- **Comment de-identification (D6):** assert a report comment contains **no** honeypot marker string,
  `Host`, or probed path — no self-identifying token survives into the posted body.
- **Signals forwarding (S4/T):** `enqueue()` with a `signals` array + `confidence` + a `bad_bot`-class
  category persists them on the row (queue contract) and the drained POST body carries `signals` (the
  same object, JSON-encoded), `confidence`, and the `bad_bot` category; `enqueue()` with **no** signals
  posts the byte-for-byte existing body (no `signals`/`confidence` keys) — proving the field is additive
  and the default path unchanged. Assert the guard ladder, dedup, cap, and the decision-N/SF-6/SF-7
  branches behave identically with and without signals. Assert the forwarded `signals` object carries no
  detector-signature string (fingerprint-safety, §6).
- **Queue contract tests:** `PdoSqliteReportQueue` against a temp SQLite file — push/take/delete/
  attempts/dedup/daily round-trips; `sensor_id` persistence in `mainnet_meta`; confirm `mainnet_*`
  tables are independent of `abuse_*`; a row pushed **with** `signals`/`confidence` round-trips through
  `take()` intact, and a row pushed **without** them reads back `NULL` (additive-column back-compat).
- **7.3 compatibility:** owned by the **`metrictower/mainnet-client` package's own 7.3 CI** (F), not
  by piece C — this supersedes D9. B's app suite only exercises the wiring against the re-exported
  package.
- **Live swap test (ties to A1 §11):** point `Reporter` at a local mainnet base URL; assert a
  report yields `2xx`. This is the mirror of the A1 "swap test": it proves the wire body/header shape
  is swap-compatible and that repointing works through B's injected base URL end to end.
- **App integration:** with both reporters wired, one hit enqueues one row in each queue; drain of
  each is independent.

## 8. Key decisions I made (confirm at review)

1. **Reporter lives in the `metrictower/mainnet-client` package** (`Funnypot\Mainnet\Reporter`),
   which `funnypot-core` `require`s and re-exports (decision F — supersedes the original "reporter in
   core" recommendation). App + WordPress (D) + Laravel (E) share one reporter and one set of
   invariants via that package; non-honeypot consumers depend on it directly. B's scope is the app +
   core wiring to it.
2. **Storage is abstracted behind a `ReportQueue` contract**, with core shipping only a
   `PdoSqliteReportQueue`. Core stays framework-free and pulls no hard DB dependency; D binds `wpdb`,
   E binds Laravel `DB`. (Core currently has no PDO/SQLite anywhere — `src/Store` is a PHP-array
   store — so forcing SQLite into core would be a new dependency; the contract avoids that.)
3. **Mainnet is the default destination, key-gated; AbuseIPDB is optional/off-by-default (D2 —
   resolved).** The app keeps `AbuseIpdb` as an independent, off-by-default path (its own key) and
   runs `Reporter` as the shipped default, active only when `MAINNET_KEY` is set. Both drain
   independently with their own `mainnet_*` vs `abuse_*` dedup/cap tables; the app may run
   mainnet-only, AbuseIPDB-only, both, or neither. No piece ever defaults to the AbuseIPDB host.
   Folding AbuseIpdb into the core base is deferred to a fast-follow.
4. **Written to PHP 7.3 from birth** in the standalone package (independent of piece C's core-floor
   work), using curl-with-stream-fallback transport — so it drops into old-PHP WordPress hosts without
   rework. The package carries its own 7.3 CI (supersedes D9).
5. **`MAINNET_BASE_URL` is a bare base URL (host only), not a full endpoint (D1).** It defaults to the
   mainnet placeholder host and is overridden for staging/local; the reporter appends `/v1/report`
   itself. The key is `MAINNET_KEY`. Exact prod host/domain is an A1 open decision (A1 §12) — I used
   `https://api.funnypot.<tld>` as the placeholder.
6. **Status-only, with a `429`-code exception (SF-7 / decision N)** — the success body is not parsed
   (mainnet's `{data:{ipAddress,abuseConfidenceScore}}` needs no client handling yet), but a `429`
   response has its Error `code` read (`duplicate_report` → drop, `quota_exhausted` → park the
   breaker) and its `Retry-After`/`X-RateLimit-Reset` headers read to set the breaker `until`. This
   is the minimum body/header read the fail-open cooldown requires.
7. **Separate `mainnet_*` tables** (not shared rows with `abuse_*`) so the two destinations dedup and
   cap independently — a mainnet 5xx retry must not suppress an AbuseIPDB report of the same IP.
8. **The report path carries an optional, additive `signals` payload the reporter only forwards (S4/T).**
   `enqueue()` accepts an optional `signals` object + signal-weighted `confidence` (a `bad_bot`-class
   category may accompany them); they are persisted on the queue row (nullable `mainnet_queue` columns)
   and folded into the drain POST body when present, omitted otherwise (body byte-for-byte unchanged).
   The reporter never computes, scores, or interprets the signals — S1 computes them in core's
   `classify()`, S3 fuses them in funnypot-policy, and B only wires the forwarding path; the honeypot app
   forwards none until funnypot-policy (M/S) lands. Chosen over a separate signal-report endpoint so the
   drain/dedup/cap/decision-N envelope is untouched and one report carries both the abuse assertion and
   its request-shape evidence.

## 9. Dependencies on other pieces

- **A1 · mainnet-api (hard, runtime):** B POSTs to A1's `POST /v1/report` and needs an operator-issued
  `internal`-tier key (A1 §8). B's report shape is fixed by the parity reference A1 also follows; the
  A1 "swap test" (A1 §11) and B's live swap test are the same proof from both ends.
- **C · funnypot-core → PHP 7.3 (related, not blocking):** the reporter's 7.3 conformance is now the
  **`metrictower/mainnet-client` package's own CI** (F), not C's matrix — this **supersedes D9**. C
  still lowers funnypot-core's own floor to 7.3 (core must run everywhere the package does), and core
  gains a `require` on the 7.3 package, but C no longer polices the reporter source.
- **D · honeypot-wordpress (dependent):** D reuses `Reporter` and supplies a `wpdb`-backed
  `ReportQueue`. D depends on B existing in core and on C (PHP 7.x hosts).
- **E · honeypot-laravel (dependent):** E reuses `Reporter` with a Laravel `DB`-backed
  `ReportQueue`. Independent of D; depends on B in core.
- **M · funnypot-policy / S · request-shape signals (producer, not blocking):** funnypot-policy computes
  the S signals (core `classify()` per S1, composite per S3) and, via its adapter, forwards them + a
  `bad_bot`-class category + a signal-weighted `confidence` to `Reporter::enqueue()` (T5 payload shape).
  B ships the forwarding path now; it stays inert (no signals posted) until funnypot-policy lands, so B
  does not block on M/S.
- **funnypot app (this repo's consumer):** AppConfig + `demo/index.php` + `demo/listen.php` +
  new `demo/mainnet-drain.php` wiring, and the `composer update metrictower/funnypot-core` pull once
  the core component is pushed.

---

## Review resolutions applied (2026-08-19)

- **D1** — Reporter now reads `MAINNET_BASE_URL` (scheme + host only, **no path**) and **appends
  `/v1/report` itself**; key renamed to `MAINNET_KEY`. Replaced the full-endpoint
  `FUNNYPOT_MAINNET_URL` default with a bare base-URL default throughout: §1, §2, §3 diagram, §4.1
  constructor (`$endpoint` → `$baseUrl`, host-only), §4.4, §5, §8.5.
- **D2** — Reporting default destination = mainnet, **active only when `MAINNET_KEY` is set** (inert
  otherwise, mirroring AbuseIpdb's empty-key skip). Dropped the `FUNNYPOT_MAINNET_REPORT` toggle and
  the "confirm dual-report vs mainnet-primary" open question; AbuseIPDB is now stated as optional/
  off-by-default, and no piece defaults to the AbuseIPDB host: §1, §2 non-goals, §4.4, §5, §8.3.
- **D3** — Added a persisted per-install **`sensor_id`**: `ReportQueue::sensorId()` generates a v4
  UUID on first run (from `random_bytes`, **not** a hardware id) into a new `mainnet_meta` row and it
  is sent on every report; noted client dedup/cap stays per attacker-IP while server distinctness is
  by `source_ip` (A1 owns): §2, §4.1, §4.2, §5, §6, §7.
- **D6** — Added the invariant that the report **comment carries no self-identifying token** (no
  honeypot marker / `Host` / probed path); fixed the ported-comment shape note (`HoneypotController.php:241`)
  and a de-identification test: §4.4, §6, §7.
- **D7** — Documented that the **reported source IP defaults to `REMOTE_ADDR`**, with XFF trusted only
  behind operator-configured trusted proxies, and named it the shared policy D/E mirror: §4.4, §6.
- **D9 / Nit** — Stated `src/Report/` is authored 7.3-clean but **B stands up no separate 7.3 CI** —
  C's gate polices it as one matrix row. Corrected the 7.3 rules to **keep scalar/array parameter
  types** (only typed *properties* are de-typed), added `nullsafe` to the forbidden list, and typed
  the `$baseUrl/$apiKey/$dailyCap/$dedupHours` params accordingly: §2, §4 intro, §4.1, §6, §7, §9.
- **Nit (429)** — Drain now **special-cases `429` to re-queue** (rate-limit back-off) instead of
  permanent-dropping it; other 4xx still drop: §3 diagram, §4.1 drain docstring + port notes, §7.
  *(Superseded by the SF-7 change below: `429` now branches on the Error `code` — `duplicate_report`
  drops, `quota_exhausted` parks — instead of an unconditional re-queue.)*

### F relocation (program decision F, 2026-08-19)

- **Reporter relocated out of core.** The reporter + its queue/transport classes move from
  `funnypot-core/src/Report/` (old `Funnypot\Report\*`) into the new standalone composer package
  **`metrictower/mainnet-client`** (`Funnypot\Mainnet\`, `Funnypot\Mainnet\Reporter`, PHP >= 7.3).
  `funnypot-core` now **`require`s and re-exports** the package; WordPress (D) / Laravel (E) get it
  transitively; non-honeypot consumers depend on it directly. Namespace/class/path references updated
  throughout (top banner, §1, §2, §3 diagram + "where it lives", §4, §6, §8, §9).
- **B's scope narrowed to wiring.** B no longer authors the reporter; its deliverable is wiring the
  funnypot app + core to the relocated `Funnypot\Mainnet\Reporter` (AppConfig, `demo/*`,
  `entrypoint.sh`, `composer` require/update). §2 gained a scope-split note; §7 flags that the
  reporter/queue/transport unit tests are the package's (F), with B owning the app-integration +
  live-swap tests.
- **Supersedes D9.** D9's "fold `src/Report/` into piece C's 7.3 matrix" no longer applies — the code
  is not in core, so the package carries its own 7.3 CI. C still lowers core's own floor to 7.3 and
  core `require`s the 7.3 package (§2, §6, §7, §9, decisions 1/4).
- **D1/D2/D3/D6/D7 intact.** The base-URL/key, key-gated posture, `sensor_id`, comment
  de-identification, and `REMOTE_ADDR` decisions are unchanged — they now describe the F package's
  `Reporter` behavior that B wires and consumes.

### Decision N + future-proofing (SF-6, SF-7) (2026-08-19)

Applies the canonical fail-open cooldown (decision **N**, futureproofing review §5) and its two
drain-side items to the Reporter's `drain()` contract B wires against. The Reporter is authored in
`metrictower/mainnet-client` (F, the breaker owner); these are the behavioral criteria the relocated
`drain()` must meet and that B's `demo/mainnet-drain.php` worker + D/E drains rely on.

- **SF-6 — bounded drain tick.** `drain()` gains a resilience envelope: a per-tick **wall-clock budget
  (10s)**; **abort after 3 consecutive transport failures**, writing the shared decision-N marker so
  the next tick short-circuits; **max-attempts / max-age** drop on re-queued rows; a **hard queue cap**
  enforced on `ReportQueue::push()` (oldest dropped). Reason: D/E can drain inside a loopback
  WP-Cron / scheduler request, so an outage must never serially burn `limit × timeout` seconds or grow
  the queue table unbounded. Updated: §3 diagram, §4.1 docstring + port notes, §4.2 `push` contract,
  §6 (new drain-bounded invariant), §7 (drain-resilience tests).
- **SF-7 — `429` branches on the Error `code`, never loops.** The earlier "unconditionally re-queue
  every 429" behaviour is superseded. `429 code=duplicate_report` → **drop** (re-queue at most once
  past its 15-min bucket); `429 code=quota_exhausted` → **park** per decision N (stop the tick, trip
  the breaker with `until` from `Retry-After` / `X-RateLimit-Reset`). **Only the quota + transport
  classes trip the breaker**; a duplicate-429 never does. This required reading the `429` body `code`
  and the retry headers — the "status-only, no body parse" posture (§2 non-goal, §8 decision 6) is
  amended to a **`429`-only** body/header read. Updated: §2 non-goals, §3 diagram, §4.1 docstring +
  port notes, §6 (new `429`-is-two-faults invariant), §7 (`429`-code branch tests), §8 decision 6.
- **N — consult the shared marker first.** Before the first POST a tick checks the decision-N breaker
  marker and **skips the whole tick while OPEN** (zero socket work). The marker is F's single
  `mnc:breaker` record (persistent cache, `sys_get_temp_dir()` filemtime fallback); B's drain and D/E
  drains all read/write the same marker. Updated: §3 diagram, §4.1 docstring, §6, §7.
- **Canonical numbers (decision N):** drain budget **10s**, abort at **3** consecutive transport
  failures, drain limit **200/tick**; breaker threshold 5 / transport cooldown 60s ±20% jitter and the
  quota `until` cap (6h) are F's to own — B's drain only writes the transport-abort marker and honors
  OPEN.

### S/T signals + telemetry (2026-08-19)

Adds the optional request-shape **`signals`** payload (decisions **S4** and **T5**) to the report path.
The signals themselves are produced elsewhere — S1 computes the individual signals in core's
`classify()`, S3 fuses the composite in funnypot-policy — so B's role is strictly to **forward** what the
policy computed. The addition is purely additive: absent signals ⇒ the byte-for-byte existing body, and
the drain/dedup/daily-cap/decision-N/SF-6/SF-7 behavior is untouched.

- **S4 — report carries the optional signals payload.** `enqueue()` gains optional `signals`
  (`array<string,mixed>`, forwarded verbatim) and `confidence` (`float`, signal-weighted) params; a
  `bad_bot`-class `categories` value may accompany them. They are persisted on the queue row and
  `drain()` folds `signals` (JSON) + `confidence` into the POST body when present, omitted otherwise.
  Updated: §2 v1 + non-goals, §4.1 signature + enqueue/drain docstrings + port note (6), §4.2 `push`
  row contract, §5 report body, §8 decision 8.
- **T — forward-only, low-trust, no read-path change.** The reporter never scores or interprets the
  signals (T2's low-trust posture is mainnet's concern; report-carried signals are report evidence per
  T1). No new endpoint, no synchronous work added — the forwarding rides the existing enqueue→drain path.
- **Storage.** `mainnet_queue` gains two **nullable, additive** columns — `signals TEXT` (JSON) and
  `confidence REAL` — so signals survive `enqueue → drain`; `NULL` for reports without policy signals,
  keeping the table backward-compatible. Updated: §4.2 prose, §5 DDL.
- **Fingerprint-safety.** The `signals` object carries request-shape observations only (missing-header
  flags, self-consistency flags, UA class, the **digit-stripped/sorted** header fingerprint, local
  anomaly summary) — never a scanner/matcher signature string, and no detection logic enters the
  reporter — so CLAUDE.md invariant #1 is preserved. Updated: §6 (new signals invariant).
- **App wiring.** `maybeReport()` passes **no** signals yet (the honeypot has no policy computing them);
  the parameter path is present so a later funnypot-policy adapter forwards its S signals without another
  Reporter change. Updated: §4.4, §9 (M/S producer dependency).
- **Tests.** Signals-forwarding (present ⇒ body carries `signals`/`confidence`/`bad_bot`; absent ⇒
  unchanged body), queue round-trip of the nullable columns, and a no-detector-signature assertion.
  Updated: §7.
