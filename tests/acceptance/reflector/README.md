# Pinned reflector acceptance

This is the manual, pre-release scanner-in-the-loop proof for the FP-0286 XSS reflector. It is
deliberately separate from the ordinary golden acceptance job. Committing this harness is not a
successful acceptance receipt: the manual workflow must run on the reviewed candidate, its receipt
must pass independent review, and `composer check` must still pass before a v0.7.0 tag is selected.

## Fixed envelope

Run from a clean checkout with no arguments:

```bash
bash tests/acceptance/reflector/run-reflect.sh
```

The command has one online phase: Docker builds the fixture from the pinned linux/amd64 PHP manifest
and downloads the two exact scanner archives in `versions.json`. `download.php` refuses an archive
whose byte count or SHA-256 differs before extraction. The Nuclei template is the unmodified single
file at its immutable source commit; the three complete upstream notices are retained under `notices/`.

The execution phase is one read-only container with `--network=none`; PHP and both scanners share that
namespace and PHP binds only `127.0.0.1:8898`. There are no published ports, host networking, Docker
socket, secrets, callback service, browser or update/download path. The host launcher fixes the target
to `http://127.0.0.1:8898/products/quick-search?q=probe`, drops all capabilities, enables
no-new-privileges, and applies 2 CPU, 2 GiB, 128 PID and eight-minute limits. `/tmp` is a bounded tmpfs;
only the dedicated evidence directory is writable. The launcher refuses a dirty tree or an existing
output directory instead of overwriting evidence.

Each scanner runs sequentially against a freshly started full-core responder in two modes:

- `authorized`: attack emulation and isolated-origin intent are on, with a test-only literal-true
  authorizer valid only inside this throwaway loopback namespace;
- `unauthorized`: otherwise identical, but the authorizer is null. The inert alphanumeric baseline may
  still reflect; raw legacy/escalation payloads must close.

The dedicated router admits only `GET /products/quick-search` (and its optional trailing slash) before
dispatching through `Honeypot::default()` with the committed compiled index and fixed persona. It
records the real winning `servedBy` owner, emitted headers and body. Off-path traffic is a distinct
`router-reject` record and a gated null response is a distinct `core-null` record; neither can masquerade
as a response with missing owner metadata.

## Bounds and receipt

The container enforces independent 90-second scanner/mode deadlines, a 512-request responder ceiling,
an aggregate 16 MiB receipt-inclusive evidence ceiling, 512 KiB process file limits and a tighter
256 KiB responder-record limit. It terminates only its recorded child
PIDs with bounded grace. Timeout, overflow, truncation, missing tools, wrong versions, scanner hard
errors, malformed output, request errors or a dead responder fail the job. Dalfox exits 0 for clean,
1 for findings and 2 for hard error; Nuclei findings retain its normal zero exit, while request/error
logs are checked separately. No failure is converted to success.

`.reflector-acceptance-output/receipt.json` uses the closed
`funnypot.reflector-acceptance.v1` schema verified by `ReceiptVerifier.php`. It binds scanner versions,
the pin file, core tree and template hashes; exact invocation; start/end/exit; request and output counts;
parsed scanner output; and bounded request/response records. The verifier requires:

- every authorized Nuclei `reflected-xss` finding correlated to its exact recorded method, raw
  path/query, response status and complete body, with its numeric breakout in the actual
  escalation-owned response, and a null-authorizer raw-gate control;
- ordered Dalfox discovery, exact special-character and generated-tag requests, with discovery owned
  by the baseline and special-character reflection owned by escalation; final `type`,
  `detection_method` and `confidence` remain separate and do not claim browser execution;
- all seven exact FP-0286 headers on escalation responses. Baseline and legacy `attack-xss` responses
  retain their real precedence and bytes; a legacy generated tag correlates only the matched tag
  substring, not an attribute-breakout prefix that core did not reflect;
- every Dalfox finding bound to its exact recorded method and raw path/query plus complete body.
  Its pinned producer stores body-only response evidence and reconstructs a request whose Host
  omits the port; Nuclei instead reports a dumped HTTP response. A shared process marker cannot
  substitute for a matching exchange. Generated non-handler tags, form-encoded spaces and
  attribute-only probes can legitimately belong to escalation; invalid decoded slots remain empty;
- no gated raw response in unauthorized mode, and no unknown, spoofed, absent or impossible owner.

The pure `tests/ReflectorAcceptanceContractTest.php` feeds actual full-core records through the
verifier with synthetic scanner envelopes (not a live receipt). It exercises positive ownership
and negative per-finding correlation, including an extra invalid finding after a valid one, without
opening sockets or starting tools. Locally it is safe to run that file alone. Do not run this live
harness on a development agent: Docker/scanner execution is reserved for the manual CI/operator gate.

## Pinned provenance

`versions.json` is the closed source of truth. It selects Nuclei v3.11.1, Dalfox v3.2.2's upstream
static-musl x86_64 asset, the linux/amd64 child of `php:8.3-cli-bookworm`, and the immutable upstream
`reflected-xss.yaml`. Its URLs, source commits, archive byte counts and hashes were checked against
the corresponding release/source metadata before this packet was written. The image build verifies
the actual archive bytes; the still-required manual run verifies executable compatibility and behavior.

The evidence-format contract is grounded in the pinned Dalfox
[`build_request_text` and finding producers](https://github.com/hahwul/dalfox/blob/7bb684fdf48959d10c6a6ac24d4a190361c58c8f/src/scanning/mod.rs)
and [64 KiB evidence bound](https://github.com/hahwul/dalfox/blob/7bb684fdf48959d10c6a6ac24d4a190361c58c8f/src/scanning/result.rs),
plus Nuclei's [dumped request/response fields](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/pkg/output/output.go).
These are format references, not vendored implementations. Our small responder bodies must match in
full; truncated evidence is not proof and cannot turn the manual release gate green.
