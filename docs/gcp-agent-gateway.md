# swarmsheriff behind Google Agent Gateway

Agent Gateway is the network boundary Google puts around agents on Gemini Enterprise Agent Platform. Agent-to-Anywhere (egress) traffic from those agents to MCP servers, APIs and public endpoints passes through it, and it delegates authorization to Service Extensions. swarmsheriff can run as one of those extensions, so the company data policy that guards a laptop's model calls also governs what agents on Google Cloud send out.

This page covers the extension. The rest of the Google side (Gemini and Vertex AI through the local proxy, Gemini CLI and Antigravity hooks) is in the README.

Status: built and tested in-process against the ext_proc protocol. It has not been run against a live Agent Gateway yet, so treat the resource files below as the shape of the setup and check them against Google's current docs before relying on them.

## How it works

Agent Gateway sends `CONTENT_AUTHZ` traffic to an authorization extension over gRPC, using Envoy's `ext_proc` protocol in `FULL_DUPLEX_STREAMED` mode, HTTP/2 with TLS on port 443. For each request swarmsheriff:

1. Reads the destination from `:authority` and the model, when there is one, from the body or the Gemini path.
2. Answers the request headers, removing any `X-Swarmsheriff-Labels`, `X-Swarmsheriff-Agent` and `X-Swarmsheriff-Credential` headers so they never reach the destination.
3. Holds the body chunks in memory until the body ends (at most `-proxy-max-mb`), so a secret split across chunks is still seen.
4. Runs the same `judge` step as the proxy: SwarmSentinel credential resolution when `-sentinel` is set, the decision pipeline, the decision event and the metrics row.
5. Either hands the body back to the gateway unchanged, or answers with an immediate 403 carrying the same error JSON the proxy sends (Google's shape for `*.googleapis.com`, the Anthropic/OpenAI shape for other hosts). A body over the cap gets a 413 in every mode.
6. Passes the response back chunk by chunk, reading only the token-usage counts on the way.

Report mode applies here exactly as in the proxy: the request goes through and the decision is logged with `enforced=false`. Bodies are never stored or logged.

The MCP JSON-RPC body of a tool call (`tools/call` with its `arguments`) is scanned like any other request text, so a class rule matches a secret in tool arguments as it would in a prompt. List each MCP server's host under a destination category in the policy; an unlisted host gets each class's strictest action.

## Run it

The extension needs a policy, a TLS certificate and an address the gateway can reach in your VPC:

```sh
./swarmsheriff -policy policy.json \
  -gateway-listen 10.0.0.5:443 -gateway-cert server.pem -gateway-key server-key.pem
```

It can run alongside the local proxy (`-proxy`) in the same process; both share the policy, the sink and `-require-credential`. Google's docs say the extension does not validate the server certificate, so a self-signed certificate works, but TLS itself is required.

## Register it with the gateway

Authorization extension (`swarmsheriff-authz-extension.yaml`). `service` is the FQDN the gateway resolves inside your VPC; DNS peering must exist between the Agent Gateway project and that network.

```yaml
name: swarmsheriff-authz
service: swarmsheriff.internal.example
failOpen: false
timeout: 1s
```

```sh
gcloud beta service-extensions authz-extensions import swarmsheriff-authz \
  --source=swarmsheriff-authz-extension.yaml --location=REGION
```

Authorization policy (`swarmsheriff-authz-policy.yaml`) bound to the egress gateway:

```yaml
name: swarmsheriff-content-authz
target:
  resources:
  - "projects/PROJECT_ID/locations/REGION/agentGateways/AGENT_GATEWAY"
policyProfile: CONTENT_AUTHZ
action: CUSTOM
customProvider:
  authzExtension:
    resources:
    - "projects/PROJECT_ID/locations/REGION/authzExtensions/swarmsheriff-authz"
```

```sh
gcloud network-security authz-policies import swarmsheriff-content-authz \
  --source=swarmsheriff-authz-policy.yaml --location=REGION
```

An egress gateway takes up to four authorization policies, so swarmsheriff can sit next to IAP (`REQUEST_AUTHZ`) and Model Armor (`CONTENT_AUTHZ`). Google does not guarantee the order of several policies with the same profile.

## Limits

- **It sees only what the gateway sends it.** Traffic that does not cross Agent Gateway, and anything a policy's match rules exclude, never reaches swarmsheriff. Google's docs do not say whether an agent's own model calls to Vertex AI are routed through the gateway or only authorized there.
- **CONTENT_AUTHZ may fail open.** `failOpen: false` is the documented default, and the codelab samples set it to `true`. A field report says CONTENT_AUTHZ in FULL_DUPLEX_STREAMED fails open on connection and header failures whatever the setting. Only REQUEST_AUTHZ is described as reliably fail-closed, and swarmsheriff does not implement REQUEST_AUTHZ yet.
- **No gateway identity yet.** Every agent behind the gateway has a SPIFFE ID, but Google does not document passing it to extensions, so decisions record the declared `X-Swarmsheriff-Agent` header or a SwarmSentinel engine identity, never the SPIFFE ID.
- **No client authentication.** The gateway presents no client certificate the docs describe. Any host that can reach the port can ask for decisions, whose messages name classes and owners, and add decision rows to the metrics. Allow only the gateway's PSC interface range in your VPC firewall rules.
- **Ingress gateways take one CONTENT_AUTHZ policy.** On a client-to-agent gateway, swarmsheriff would replace Model Armor rather than run beside it, so use it on egress.
- **Latency.** The request is held until its body is complete, plus the pipeline's own time (tens of microseconds on the eval corpus, low milliseconds on large real requests). Streaming responses are not delayed.

## Elsewhere on the Google side

| Scenario | What swarmsheriff does |
| --- | --- |
| Agents on Google Cloud behind Agent Gateway | Decides and, in enforce mode, blocks through this extension |
| Scripts and SDK apps using a Gemini API key | Local proxy via `GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8788/generativelanguage.googleapis.com` |
| Vertex AI from SDKs | Local proxy; the model is read from the Vertex path; not yet tested with a real Vertex client |
| Gemini CLI with an API key (paid keys, Code Assist Standard or Enterprise) | Local proxy, plus `swarmsheriff hook --print-config gemini-cli` for activity metrics |
| Antigravity IDE, 2.0 desktop and the `agy` CLI, signed in with Google | Activity metrics through hooks (`--print-config antigravity`) and process inventory; model traffic goes straight to Google over TLS and cannot be inspected or blocked locally |
| gemini.google.com and AI Studio in Chrome | Site detection (host only) and the clipboard guard |
