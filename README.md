# swarmsheriff

swarmsheriff is a single-binary Go tool that keeps company information from leaking to LLMs and AI services. It runs on a workstation and works with any agent or AI tool: coding agents, chat apps, browser chats, scripts, and multi-agent swarms.

What counts as sensitive is up to the company. Source code, prompts, product plans, customer data, legal material and financials are all defined as data classes in a policy file, so adding a class never needs a code change.

## What it does

swarmsheriff has two jobs.

**Sense.** It watches the clipboard, the AI apps running on the machine, and the AI sites open in Chrome. It scans text for secrets, personal data and company keywords, measures agent activity through Claude Code, Antigravity and Gemini CLI hooks, and records everything in a local, body-free metrics database with a web dashboard on top.

**Decide and enforce.** It sits on the request path to LLM APIs as a loopback reverse proxy, classifies each request against the policy, and returns a verdict of `allow`, `translate`, `hold` or `block`. Report mode is the default: the request goes through and the verdict that would have applied is logged. Enforcement is switched on per class, never globally. Each decision can also be sent to the SwarmSentinel policy engine and flight recorder.

A local tool stops accidents, not deliberate exfiltration through another device. swarmsheriff can block only requests that agents send through its proxy. For browser chats it can at most replace a sensitive clipboard with a notice.

## Status

| Area | State |
| --- | --- |
| Clipboard, process and Chrome tab watching | Built |
| DLP scan (secrets, PII, user keywords) | Built |
| Clipboard guard | Built, off by default |
| Loopback `/scan` and `/healthz` endpoint | Built |
| Metrics store (SQLite), `metrics` CLI and local dashboard | Built |
| Agent lifecycle metrics from Claude Code, Antigravity and Gemini CLI hooks | Built |
| Declarative hook adapters for new agents (JSON, no recompile) | Built |
| Policy file, decision pipeline, LLM reverse proxy | Built, report mode by default |
| Classifier interface with a Jev (OpenRouter) client | Built, not yet calibrated against live traffic |
| Decision events to a file sink and to SwarmSentinel | Built |
| Gemini and Vertex AI through the proxy | Built |
| Google Agent Gateway authorization extension (CONTENT_AUTHZ) | Built, off by default; not yet run against a live gateway |
| `-eval` against a labeled corpus | Built; seed corpus is still small |
| Surrogate translation | Interface stub only |

## Build

Go 1.27.1 or later. The dependencies outside the standard library are pure Go: `modernc.org/sqlite` for the metrics store, and `google.golang.org/grpc` with Envoy's `go-control-plane` types for the Google Agent Gateway extension. The binary builds without cgo and cross-compiles for macOS, Linux and Windows.

```sh
go build -o swarmsheriff ./cmd/swarmsheriff
go vet ./...
go test ./...
```

## Quick start

Watch the clipboard and AI apps, with keyword rules and without logging raw clipboard text:

```sh
./swarmsheriff -quiet -log-content=false -dlp-keywords=CONFIDENTIAL,ProjectX
```

Print the current clipboard once and exit:

```sh
./swarmsheriff -once
```

Run the LLM proxy with a policy file:

```sh
cp policy.example.json policy.json
./swarmsheriff -policy policy.json -proxy 127.0.0.1:8788
```

Then point agents at it, with the upstream host as the first path segment:

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788/api.anthropic.com
export OPENAI_BASE_URL=http://127.0.0.1:8788/api.openai.com/v1
export GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8788/generativelanguage.googleapis.com
```

Gemini requests may carry the API key in a `?key=` query parameter; it is forwarded upstream and never logged. A blocked Gemini request gets a 403 in Google's own error shape (`PERMISSION_DENIED`), so the Gemini SDKs and Gemini CLI show the reason. Gemini CLI uses the base URL only with API-key auth, not with "Login with Google".

Optional request headers, stripped before forwarding: `X-Swarmsheriff-Labels` (comma-separated source labels), `X-Swarmsheriff-Agent` (declared agent ID) and `X-Swarmsheriff-Credential` (a SwarmSentinel agent credential, resolved to an engine-issued identity when `-sentinel` is set).

## Google Agent Gateway

Agents running on Google Cloud reach models, APIs and MCP servers through Agent Gateway. swarmsheriff can sit behind it as a custom authorization extension, so the same policy file governs those agents too:

```sh
./swarmsheriff -policy policy.json -gateway-listen 10.0.0.5:443 \
  -gateway-cert server.pem -gateway-key server-key.pem
```

The gateway streams each request to swarmsheriff (Envoy `ext_proc`, `CONTENT_AUTHZ` profile). swarmsheriff reads the whole body, decides, and either hands it back unchanged or answers with a 403. Report mode applies here too. See [docs/gcp-agent-gateway.md](docs/gcp-agent-gateway.md) for the extension and authorization policy resources and the known limits.

## Metrics, hooks and dashboard

```sh
./swarmsheriff metrics query --from 24h
./swarmsheriff metrics export --from 7d --output events.ndjson
./swarmsheriff metrics clear --yes

./swarmsheriff hook --list-agents
./swarmsheriff hook --print-config claude-code
./swarmsheriff hook --print-config gemini-cli

./swarmsheriff dashboard --listen 127.0.0.1:9090
```

The running collector also serves the dashboard on `127.0.0.1:9090` by default; `-dashboard ""` turns it off. New agents can be added by dropping a JSON adapter into `~/.config/swarmsheriff/adapters/` (see `docs/adapters/example.json`).

## Main flags

| Flag | Purpose |
| --- | --- |
| `-policy policy.json` | Policy file, required by `-proxy` and `-eval` |
| `-proxy 127.0.0.1:8788` | LLM reverse proxy, loopback only |
| `-proxy-max-mb 32` | Largest request body the proxy scans and forwards |
| `-mode report` | Override the policy's global mode; per-class mode still wins |
| `-eval testdata/corpus` | Print per-class miss and false-positive rates, then exit |
| `-classifier none` | `none` or `jev` (reads `OPENROUTER_API_KEY`) |
| `-clipboard-guard off` | `off`, `ai` or `always` |
| `-listen 127.0.0.1:8787` | Loopback `/scan` endpoint; token printed to stderr |
| `-metrics=true` | Body-free metrics in SQLite, 30-day retention by default |
| `-sentinel URL -sentinel-secret-file f` | Link to SwarmSentinel |
| `-require-credential` | Refuse proxy requests without an engine-issued credential |
| `-gateway-listen ADDR -gateway-cert f -gateway-key f` | Google Agent Gateway extension over TLS (not loopback) |

All behavior-affecting flags appear in the `swarmsheriff started` log line.

## How a request is classified

Signals are checked in order of cost and certainty:

1. Source labels from the policy and from trusted launchers.
2. Fingerprints: SHA-256 hashes of known documents or lists.
3. Patterns and keywords: the built-in DLP rules plus each class's own rules.
4. A classifier, only for text the first three steps left ambiguous and only for classes that enable it.

The first three steps are deterministic, so cleverly worded text cannot argue its way past them. By default a hosted classifier sees only features of a request (labels, document markers, length, rule counts), never the content. A class must opt in to raw content with `"classifier_raw": true`, and that choice shows in the startup log.

If the classifier times out or fails, swarmsheriff falls back to the deterministic result. An invalid policy at startup stops the program; an invalid policy on reload keeps the last good one.

## Privacy by design

swarmsheriff is careful not to become the data store it exists to protect.

- DLP results carry rule names and counts, never the matched text.
- The proxy reads request bodies in memory to decide and never stores or logs them. From responses it reads only the token-usage integers.
- API keys and authorization headers pass through to the upstream and are never logged.
- The metrics database holds kinds, labels, counts, timings and token counts only. No prompts, responses, command lines or file contents.
- Hook integration forwards event names, opaque IDs and a model name, nothing else.
- Every listener binds to loopback only, except the opt-in Agent Gateway extension, which requires TLS. Log and database files are created readable by the owner only.
- Browser watching records the host of a tab, never the path or query.

## Platforms

Clipboard reads use `pbpaste` on macOS, PowerShell `Get-Clipboard` on Windows, and `wl-paste`, `xclip` or `xsel` on Linux. Process listing uses `ps` on Unix and `tasklist` on Windows. Chrome tab watching is macOS only.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, endpoints, storage, trust boundaries and failure behavior
- [docs/CAPABILITIES.md](docs/CAPABILITIES.md): plain-language overview of what is built today
- [docs/ROADMAP.md](docs/ROADMAP.md): the phased plan through enforcement and hardening
- [docs/gcp-agent-gateway.md](docs/gcp-agent-gateway.md): running swarmsheriff as a Google Agent Gateway authorization extension
- [policy.example.json](policy.example.json): an example policy with sample classes

## Author

Prasad MK ([prasad-m-k](https://github.com/prasad-m-k))
