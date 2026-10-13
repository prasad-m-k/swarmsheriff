// Package proxy is the loopback LLM reverse proxy and the Google Agent Gateway
// ext_proc extension. Both share judge: identity, decision, event, metrics.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"swarmsheriff/internal/decide"
	"swarmsheriff/internal/events"
	"swarmsheriff/internal/llm"
	"swarmsheriff/internal/metrics"
	"swarmsheriff/internal/netutil"
	"swarmsheriff/internal/policy"
	"swarmsheriff/internal/sentinel"
	"sync"
	"time"
	"unicode/utf8"
)

// The LLM reverse proxy. Agents reach it through a base-URL override whose
// first path segment names the upstream host, for example
//
//	ANTHROPIC_BASE_URL=http://127.0.0.1:8788/api.anthropic.com
//	OPENAI_BASE_URL=http://127.0.0.1:8788/api.openai.com/v1
//	GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8788/generativelanguage.googleapis.com
//
// It does no TLS interception: the agent talks plain HTTP to loopback and the
// proxy opens its own HTTPS connection upstream.

const (
	headerLabels = "X-Swarmsheriff-Labels"
	headerAgent  = "X-Swarmsheriff-Agent"
)

var upstreamHost = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::\d{1,5})?$`)

type Proxy struct {
	decider *decide.Decider
	// SwarmSentinel link (sentinel.go). With sentinel set, a request carrying
	// headerCredential is attributed to the engine-issued identity and its
	// confidentiality labels; requireCredential refuses requests without one.
	Sentinel          *sentinel.Client
	RequireCredential bool
	sink              events.Sink
	logger            *slog.Logger
	maxBody           int64
	transport         http.RoundTripper
	Rec               metrics.Recorder

	scheme        string // "https"; tests swap in their own TLS server
	allowLoopback bool   // tests only: production refuses loopback upstreams
}

func New(d *decide.Decider, sink events.Sink, logger *slog.Logger, maxBody int64) *Proxy {
	return &Proxy{decider: d, sink: sink, logger: logger, maxBody: maxBody,
		transport: http.DefaultTransport, scheme: "https", Rec: metrics.NopRecorder{}}
}

// Start serves the proxy on a loopback address until ctx is cancelled.
func Start(ctx context.Context, addr string, p *Proxy) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("proxy address %q: %w", addr, err)
	}
	if !netutil.IsLoopback(host) {
		return fmt.Errorf("refusing to bind non-loopback address %q; use 127.0.0.1 or [::1]", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	// No ReadTimeout or WriteTimeout: streamed completions can run for minutes.
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	p.logger.Info("proxy listening", "addr", addr)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if !upstreamHost.MatchString(host) {
		writeProxyError(w, http.StatusNotFound, "not_found_error",
			"swarmsheriff: the first path segment must be the upstream host, e.g. /api.anthropic.com/v1/messages")
		return
	}
	if h, _, err := net.SplitHostPort(host); (err == nil && netutil.IsLoopback(h)) || netutil.IsLoopback(host) {
		if !p.allowLoopback {
			writeHostError(w, host, http.StatusForbidden, "permission_error", "swarmsheriff: loopback upstreams are not allowed")
			return
		}
	}

	// The body is held only for this request: scanned, forwarded, then dropped.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeHostError(w, host, http.StatusRequestEntityTooLarge, "request_too_large",
				fmt.Sprintf("swarmsheriff: request body over the %d byte scan limit", p.maxBody))
			return
		}
		writeHostError(w, host, http.StatusBadRequest, "invalid_request_error", "swarmsheriff: could not read request body")
		return
	}

	rl := p.judge(r.Context(), host, rest, r.Header, body)
	if rl.status != 0 {
		writeHostError(w, host, rl.status, rl.typ, rl.msg)
		return
	}
	d := rl.d

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = p.scheme
			pr.Out.URL.Host = host
			pr.Out.URL.Path = "/" + rest
			pr.Out.URL.RawPath = ""
			pr.Out.Host = host
			pr.Out.Header.Del(headerLabels)
			pr.Out.Header.Del(headerAgent)
			pr.Out.Header.Del(sentinel.HeaderCredential)
			pr.Out.Body = io.NopCloser(bytes.NewReader(body))
			pr.Out.ContentLength = int64(len(body))
		},
		Transport:     p.transport,
		FlushInterval: -1, // flush each write so streamed responses pass through as they arrive
		ModifyResponse: func(resp *http.Response) error {
			// Read the usage field as the body streams past, storing only the
			// token counts. The body is not buffered and content is not kept.
			tc := &tokenCapture{rec: p.Rec, model: rl.model, provider: d.Destination,
				dest: d.Destination, agentID: d.AgentID}
			resp.Body = &teeReadCloser{rc: resp.Body, tee: io.TeeReader(resp.Body, tc), done: tc.record}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == nil {
				// A *url.Error prints the full URL, and Gemini clients may put
				// the API key in its query (?key=), so log only the cause.
				var ue *url.Error
				if errors.As(err, &ue) {
					err = ue.Err
				}
				p.logger.Error("upstream failed", "dest", host, "err", err)
			}
			writeHostError(w, host, http.StatusBadGateway, "api_error", "swarmsheriff: upstream request failed")
		},
	}
	rp.ServeHTTP(w, r)
}

// ruling is what the proxy or the gateway extension does with one request:
// forward it (status 0) or answer with an error. The decision has already
// been sent to the sink and the recorder.
type ruling struct {
	d        decide.Decision
	model    string
	status   int
	typ, msg string
}

// judge resolves the agent's identity, runs the decision pipeline over one
// request body and records the decision. hdr supplies the optional
// X-Swarmsheriff-* headers; the caller strips them before forwarding.
func (p *Proxy) judge(ctx context.Context, host, path string, hdr http.Header, body []byte) ruling {
	// Gemini names the model in the path (models/gemini-2.5-pro:generateContent),
	// the others in the body.
	model := llm.RequestModel(body)
	if model == "" {
		model = llm.PathModel(path)
	}
	req := decide.Request{
		Text:        requestText(body),
		Labels:      policy.SplitList(hdr.Get(headerLabels)),
		AgentID:     strings.TrimSpace(hdr.Get(headerAgent)),
		Destination: host,
	}
	start := time.Now()
	var ident *sentinel.Identity
	if credential := strings.TrimSpace(hdr.Get(sentinel.HeaderCredential)); credential != "" && p.Sentinel != nil {
		id, err := p.Sentinel.Resolve(ctx, credential)
		if err != nil {
			// Fail closed: the request claims an engine identity nobody could confirm.
			if !errors.Is(err, sentinel.ErrUnknownCredential) {
				p.logger.Error("sentinel resolve failed", "err", err)
			}
			return p.refuse(host, nil, "identity:unverified", model, start,
				"swarmsheriff: the agent credential could not be verified with SwarmSentinel")
		}
		ident = &id
	} else if p.RequireCredential {
		return p.refuse(host, nil, "identity:missing", model, start,
			"swarmsheriff: this proxy requires an engine-issued agent credential ("+sentinel.HeaderCredential+")")
	}
	if ident != nil {
		if ident.Revoked {
			return p.refuse(host, ident, "sentinel:revoked", model, start,
				"swarmsheriff: SwarmSentinel has revoked this agent; its model requests are refused")
		}
		// Engine labels only add restrictions, like launcher labels.
		req.Labels = append(req.Labels, ident.Labels...)
		req.AgentID, req.AgentIDSource = ident.AgentID, "engine"
	}
	d := p.decider.Decide(ctx, req)
	if ident != nil {
		d.SessionID, d.TaskID = ident.SessionID, ident.TaskID
	}
	p.emit(d, model, start)
	if d.Enforced() {
		return ruling{d: d, model: model, status: http.StatusForbidden, typ: "permission_error", msg: blockMessage(d)}
	}
	return ruling{d: d, model: model}
}

func (p *Proxy) emit(d decide.Decision, model string, start time.Time) {
	ev := events.Event{Time: time.Now(), Decision: d, Model: model}
	if err := p.sink.Emit(ev); err != nil {
		p.logger.Error("event sink failed", "err", err)
	}
	p.Rec.Record(metrics.DecisionEvent(ev, ev.Time.Sub(start)))
}

// refuse blocks a request before classification, for identity and revocation
// failures, and records the decision like any other.
func (p *Proxy) refuse(host string, ident *sentinel.Identity, rule, model string, start time.Time, msg string) ruling {
	cat, ok := p.decider.Policy.Load().Category(host)
	if !ok {
		cat = decide.CategoryUnlisted
	}
	d := decide.Decision{Verdict: policy.VerdictBlock, Applied: policy.VerdictBlock, Mode: policy.ModeEnforce, Rules: []string{rule},
		Destination: host, Category: cat, Classifier: "not-needed", Confidence: 1}
	if ident != nil {
		d.AgentID, d.AgentIDSource, d.SessionID, d.TaskID = ident.AgentID, "engine", ident.SessionID, ident.TaskID
	}
	p.emit(d, model, start)
	return ruling{d: d, model: model, status: http.StatusForbidden, typ: "permission_error", msg: msg}
}

// blockMessage tells the user what happened and how to ask for an exception,
// naming classes and owners but never the matched content.
func blockMessage(d decide.Decision) string {
	what := "blocked"
	switch d.Applied {
	case policy.VerdictHold:
		what = "held for approval (approval flow not built yet, so treated as blocked)"
	case policy.VerdictTranslate:
		what = "blocked (surrogate translation not built yet)"
	}
	msg := fmt.Sprintf("swarmsheriff: request to %s %s by company data policy; classes: %s.",
		d.Destination, what, strings.Join(d.Classes, ", "))
	if len(d.Owners) > 0 {
		msg += fmt.Sprintf(" To request an exception, contact the class owner: %s.", strings.Join(d.Owners, ", "))
	}
	return msg
}

// writeProxyError writes an error body both the Anthropic and OpenAI SDKs can
// read: each looks for error.message and error.type.
func writeProxyError(w http.ResponseWriter, status int, typ, msg string) {
	writeHostError(w, "", status, typ, msg)
}

// writeHostError writes the error in the shape the upstream's own SDK reads.
func writeHostError(w http.ResponseWriter, host string, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(errorBody(host, status, typ, msg))
}

// errorBody is the JSON error for a host. Google's Gemini and Vertex SDKs
// look for error.status and error.message in
// {"error":{"code":403,"message":"...","status":"PERMISSION_DENIED"}}; every
// other host gets the shared Anthropic/OpenAI shape.
func errorBody(host string, status int, typ, msg string) []byte {
	var v any = map[string]any{"type": "error", "error": map[string]string{"type": typ, "message": msg}}
	if llm.Provider(host) == "google" {
		code := "INTERNAL"
		switch status {
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
			code = "INVALID_ARGUMENT"
		case http.StatusForbidden:
			code = "PERMISSION_DENIED"
		case http.StatusNotFound:
			code = "NOT_FOUND"
		case http.StatusBadGateway:
			code = "UNAVAILABLE"
		}
		v = map[string]any{"error": map[string]any{"code": status, "message": msg, "status": code}}
	}
	b, _ := json.Marshal(v)
	return append(b, '\n')
}

// requestText returns the text an LLM request carries. For JSON it joins every
// string value, so keys and syntax do not trigger patterns; long unbroken
// strings (base64 images, file blobs) are skipped.
func requestText(body []byte) string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		if utf8.Valid(body) {
			return string(body)
		}
		return ""
	}
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if len(t) > 1000 && !strings.ContainsAny(t, " \n\t") {
				return
			}
			b.WriteString(t)
			b.WriteByte('\n')
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			// Sorted so the same body always yields the same text.
			for _, k := range slices.Sorted(maps.Keys(t)) {
				walk(t[k])
			}
		}
	}
	walk(v)
	return b.String()
}

// teeReadCloser feeds everything read from rc into a tee sink, and runs done
// once when the body is fully read or closed. The ReverseProxy copies the body
// to the client and then closes it, so done fires after the response is sent.
type teeReadCloser struct {
	rc   io.ReadCloser
	tee  io.Reader
	done func()
	once sync.Once
}

func (t *teeReadCloser) Read(p []byte) (int, error) {
	n, err := t.tee.Read(p)
	if err == io.EOF {
		t.once.Do(t.done)
	}
	return n, err
}

func (t *teeReadCloser) Close() error {
	t.once.Do(t.done)
	return t.rc.Close()
}

// usageTokens pulls the first input/prompt token count and the last
// output/completion token count out of an LLM response, so it works for both
// a single JSON body and an SSE stream (Anthropic reports output_tokens again
// in the final message_delta; OpenAI in the final chunk; Gemini repeats a
// running usageMetadata in every chunk). Gemini counts thinking separately
// from candidatesTokenCount but bills it as output, so it is added on.
var (
	reInTokens      = regexp.MustCompile(`"(?:input_tokens|prompt_tokens|promptTokenCount)"\s*:\s*(\d+)`)
	reOutTokens     = regexp.MustCompile(`"(?:output_tokens|completion_tokens|candidatesTokenCount)"\s*:\s*(\d+)`)
	reThoughtTokens = regexp.MustCompile(`"thoughtsTokenCount"\s*:\s*(\d+)`)
)

// tokenCapture scans a response body incrementally for the usage field. It
// keeps a small tail so a count split across two chunks is still found, and
// never holds the whole body.
type tokenCapture struct {
	rec                            metrics.Recorder
	model, provider, dest, agentID string
	tail                           []byte
	inTokens, outTokens, thoughts  int64
	haveIn, haveOut                bool
}

const tokenScanOverlap = 64

func (t *tokenCapture) Write(p []byte) (int, error) {
	buf := p
	if len(t.tail) > 0 {
		buf = append(append([]byte(nil), t.tail...), p...)
	}
	if !t.haveIn {
		if m := reInTokens.FindSubmatch(buf); m != nil {
			t.inTokens, _ = strconv.ParseInt(string(m[1]), 10, 64)
			t.haveIn = true
		}
	}
	// Output is taken from the last match seen across the whole stream.
	if m := reOutTokens.FindAllSubmatch(buf, -1); m != nil {
		t.outTokens, _ = strconv.ParseInt(string(m[len(m)-1][1]), 10, 64)
		t.haveOut = true
	}
	if m := reThoughtTokens.FindAllSubmatch(buf, -1); m != nil {
		t.thoughts, _ = strconv.ParseInt(string(m[len(m)-1][1]), 10, 64)
		t.haveOut = true
	}
	if n := len(buf); n > tokenScanOverlap {
		t.tail = append(t.tail[:0], buf[n-tokenScanOverlap:]...)
	} else {
		t.tail = append(t.tail[:0], buf...)
	}
	return len(p), nil
}

func (t *tokenCapture) record() {
	if !t.haveIn && !t.haveOut {
		return // not an LLM response with a usage field
	}
	t.rec.Record(metrics.Event{Kind: metrics.KindTokenUsage, Model: t.model, Provider: llm.Provider(t.provider),
		Dest: t.dest, AgentID: t.agentID, InTokens: t.inTokens, OutTokens: t.outTokens + t.thoughts})
}
