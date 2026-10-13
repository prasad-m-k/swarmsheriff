package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"swarmsheriff/internal/metrics"
	"swarmsheriff/internal/policy"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// gatewayClient runs the extension in-process and plays Agent Gateway's side
// of an ext_proc stream.
func gatewayClient(t *testing.T, modeFlag string) (extprocv3.ExternalProcessorClient, *captureRecorder) {
	t.Helper()
	p, _, _ := newTestProxy(t, nil, modeFlag, nil)
	rec := &captureRecorder{}
	p.Rec = rec
	ln := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(srv, &gatewayExt{p: p})
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return ln.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return extprocv3.NewExternalProcessorClient(conn), rec
}

func reqHeaders(host, path string, end bool, extra map[string]string) *extprocv3.ProcessingRequest {
	hs := []*corev3.HeaderValue{
		{Key: ":authority", RawValue: []byte(host)}, {Key: ":path", RawValue: []byte(path)},
		{Key: ":method", RawValue: []byte("POST")}, {Key: "content-type", RawValue: []byte("application/json")},
	}
	for k, v := range extra {
		hs = append(hs, &corev3.HeaderValue{Key: k, RawValue: []byte(v)})
	}
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: hs}, EndOfStream: end}}}
}

func reqBody(b string, end bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
		RequestBody: &extprocv3.HttpBody{Body: []byte(b), EndOfStream: end}}}
}

func openStream(t *testing.T, c extprocv3.ExternalProcessorClient) extprocv3.ExternalProcessor_ProcessClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	s, err := c.Process(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func send(t *testing.T, s extprocv3.ExternalProcessor_ProcessClient, msgs ...*extprocv3.ProcessingRequest) {
	t.Helper()
	for _, m := range msgs {
		if err := s.Send(m); err != nil {
			t.Fatal(err)
		}
	}
}

func recv(t *testing.T, s extprocv3.ExternalProcessor_ProcessClient) *extprocv3.ProcessingResponse {
	t.Helper()
	r, err := s.Recv()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGatewayBlocksInEnforceMode(t *testing.T) {
	c, rec := gatewayClient(t, policy.ModeEnforce)
	s := openStream(t, c)
	send(t, s, reqHeaders("api.anthropic.com", "/v1/messages", false, nil))
	if recv(t, s).GetRequestHeaders() == nil {
		t.Fatal("want a headers response before the body")
	}
	// Split across chunks: the decision must see the whole body.
	send(t, s, reqBody(`{"messages":[{"content":"Plan for Proj`, false), reqBody(`ectX"}]}`, true))
	im := recv(t, s).GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != 403 {
		t.Fatalf("want an immediate 403, got %+v", im)
	}
	var body struct {
		Error struct{ Type, Message string }
	}
	if err := json.Unmarshal(im.GetBody(), &body); err != nil || body.Error.Type != "permission_error" ||
		!strings.Contains(body.Error.Message, "engineering") || strings.Contains(string(im.GetBody()), "Plan for") {
		t.Errorf("deny body = %s (%v)", im.GetBody(), err)
	}
	s.CloseSend()
	if len(rec.events) != 1 || rec.events[0].Kind != metrics.KindDecision || rec.events[0].Verdict != "block" {
		t.Errorf("events = %+v", rec.events)
	}
}

func TestGatewayReportModeForwardsUnchanged(t *testing.T) {
	c, rec := gatewayClient(t, "")
	s := openStream(t, c)
	send(t, s, reqHeaders("generativelanguage.googleapis.com", "/v1beta/models/gemini-2.5-pro:generateContent", false,
		map[string]string{"x-swarmsheriff-labels": "repo:core", "x-swarmsheriff-agent": "a1"}))
	hr := recv(t, s).GetRequestHeaders()
	if rm := hr.GetResponse().GetHeaderMutation().GetRemoveHeaders(); len(rm) != 3 || rm[0] != "x-swarmsheriff-labels" {
		t.Errorf("hint headers not stripped: %v", rm)
	}
	body := `{"contents":[{"role":"user","parts":[{"text":"ProjectX roadmap"}]}]}`
	send(t, s, reqBody(body[:20], false), reqBody(body[20:], true))
	sb := recv(t, s).GetRequestBody().GetResponse().GetBodyMutation().GetStreamedResponse()
	if string(sb.GetBody()) != body || !sb.GetEndOfStream() {
		t.Fatalf("forwarded body = %q end=%v", sb.GetBody(), sb.GetEndOfStream())
	}
	// The response streams back chunk by chunk; usage is read in flight.
	send(t, s, &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{}}})
	if recv(t, s).GetResponseHeaders() == nil {
		t.Fatal("want a response headers answer")
	}
	for i, chunk := range []string{`{"candidates":[],"usageMetadata":{"promptTokenCount":12,`, `"candidatesTokenCount":5}}`} {
		send(t, s, &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(chunk), EndOfStream: i == 1}}})
		got := recv(t, s).GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse()
		if string(got.GetBody()) != chunk || got.GetEndOfStream() != (i == 1) {
			t.Errorf("chunk %d echoed as %q", i, got.GetBody())
		}
	}
	s.CloseSend()
	s.Recv() // wait for the server to finish the stream

	var dec, tok *metrics.Event
	for i := range rec.events {
		switch rec.events[i].Kind {
		case metrics.KindDecision:
			dec = &rec.events[i]
		case metrics.KindTokenUsage:
			tok = &rec.events[i]
		}
	}
	if dec == nil || dec.Verdict != "block" || dec.Enforced || dec.Model != "gemini-2.5-pro" || dec.AgentID != "a1" {
		t.Errorf("decision = %+v", dec)
	}
	if tok == nil || tok.InTokens != 12 || tok.OutTokens != 5 {
		t.Errorf("tokens = %+v", tok)
	}
}

func TestGatewayGoogleDenyShapeAndBodyCap(t *testing.T) {
	c, _ := gatewayClient(t, policy.ModeEnforce)
	s := openStream(t, c)
	send(t, s, reqHeaders("us-central1-aiplatform.googleapis.com", "/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent", false, nil))
	recv(t, s)
	send(t, s, reqBody(`{"contents":[{"parts":[{"text":"ProjectX"}]}]}`, true))
	im := recv(t, s).GetImmediateResponse()
	if im == nil || !strings.Contains(string(im.GetBody()), `"status":"PERMISSION_DENIED"`) {
		t.Errorf("vertex deny = %+v", im)
	}

	s = openStream(t, c)
	send(t, s, reqHeaders("mcp.example.com", "/mcp", false, nil))
	recv(t, s)
	big := strings.Repeat("a", 1<<10) // the test proxy caps bodies at 1 KiB
	send(t, s, reqBody(big, false), reqBody("b", true))
	if im := recv(t, s).GetImmediateResponse(); im == nil || im.GetStatus().GetCode() != 413 {
		t.Errorf("oversized body: %+v", im)
	}
}

func TestGatewayHeadersOnlyAndTrailers(t *testing.T) {
	c, _ := gatewayClient(t, policy.ModeEnforce)
	s := openStream(t, c)
	send(t, s, reqHeaders("api.anthropic.com", "/v1/models", true, nil))
	if recv(t, s).GetRequestHeaders() == nil {
		t.Error("a clean bodiless request should continue")
	}

	s = openStream(t, c)
	send(t, s, reqHeaders("api.anthropic.com", "/v1/messages", false, nil))
	recv(t, s)
	send(t, s, reqBody(`{"messages":[{"content":"hello"}]}`, false),
		&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestTrailers{
			RequestTrailers: &extprocv3.HttpTrailers{}}})
	sb := recv(t, s).GetRequestBody().GetResponse().GetBodyMutation().GetStreamedResponse()
	if string(sb.GetBody()) != `{"messages":[{"content":"hello"}]}` || sb.GetEndOfStream() {
		t.Errorf("body before trailers = %q end=%v", sb.GetBody(), sb.GetEndOfStream())
	}
	if recv(t, s).GetRequestTrailers() == nil {
		t.Error("want a trailers answer")
	}
}

func TestGatewayLogsNoContent(t *testing.T) {
	p, logs, _ := newTestProxy(t, nil, policy.ModeEnforce, nil)
	g := &gatewayExt{p: p}
	st := &gatewayRequest{hdr: map[string][]string{}}
	g.handle(context.Background(), st, reqHeaders("api.openai.com", "/v1/chat/completions", false,
		map[string]string{"authorization": "Bearer sk-secret-value"}))
	g.handle(context.Background(), st, reqBody(`{"messages":[{"content":"ProjectX secret plan"}]}`, true))
	for _, banned := range []string{"secret plan", "sk-secret-value"} {
		if strings.Contains(logs.String(), banned) {
			t.Errorf("log carries %q: %s", banned, logs)
		}
	}
}

func TestStartGatewayNeedsTLS(t *testing.T) {
	p, _, _ := newTestProxy(t, nil, "", nil)
	if err := StartGateway(context.Background(), "127.0.0.1:0", "", "", p); err == nil {
		t.Error("started without a certificate")
	}
}

// The real listener over TLS, as Agent Gateway reaches it.
func TestStartGatewayServesTLS(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "swarmsheriff.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	p, _, _ := newTestProxy(t, nil, policy.ModeEnforce, nil)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- StartGateway(ctx, addr, certFile, keyFile, p) }()
	t.Cleanup(func() {
		cancel()
		if err := <-errc; err != nil {
			t.Errorf("serve: %v", err)
		}
	})

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var s extprocv3.ExternalProcessor_ProcessClient
	for i := 0; i < 50; i++ { // the listener may still be starting
		if s, err = extprocv3.NewExternalProcessorClient(conn).Process(ctx); err == nil {
			if err = s.Send(reqHeaders("api.anthropic.com", "/v1/messages", false, nil)); err == nil {
				if _, err = s.Recv(); err == nil {
					break
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	send(t, s, reqBody(`{"messages":[{"content":"ProjectX"}]}`, true))
	if im := recv(t, s).GetImmediateResponse(); im == nil || im.GetStatus().GetCode() != 403 {
		t.Errorf("over TLS: %+v", im)
	}
}
