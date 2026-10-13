package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// The Google Agent Gateway extension. Agent Gateway delegates CONTENT_AUTHZ
// authorization policies to a Service Extensions authorization extension: a
// gRPC service speaking Envoy ext_proc in FULL_DUPLEX_STREAMED mode, reached
// over HTTP/2 with TLS. swarmsheriff serves that protocol so the same company
// data policy that guards a laptop's model calls also guards traffic leaving
// agents on Google Cloud (MCP tool calls, model and API requests).
//
// The request body is buffered in memory, up to the proxy's body cap, so the
// pipeline sees it whole; then it is sent back to the gateway unchanged or the
// request is answered with a 403. It is never stored or logged. Response
// bodies stream back chunk by chunk and are scanned only for token counts.
//
// Unlike the proxy, this listener is not loopback: the gateway calls it from
// Google's side over the VPC. It is off unless -gateway-listen is set, and it
// refuses to start without a TLS certificate.

type gatewayExt struct {
	extprocv3.UnimplementedExternalProcessorServer
	p *llmProxy
}

// gatewayRequest is the per-stream state: one HTTP request and its response.
type gatewayRequest struct {
	host, path string
	hdr        http.Header
	body       []byte
	tooBig     bool
	done       bool // a decision was made and the request body sent on
	tokens     *tokenCapture
}

func (g *gatewayExt) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	st := &gatewayRequest{hdr: http.Header{}}
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled {
			return nil
		}
		if err != nil {
			return err
		}
		resp, err := g.handle(ctx, st, req)
		if err != nil {
			return err
		}
		// In observability mode the gateway ignores answers; decisions are
		// still recorded, nothing is sent.
		for _, r := range resp {
			if req.GetObservabilityMode() {
				break
			}
			if err := stream.Send(r); err != nil {
				return err
			}
		}
		if st.tokens != nil && isLastResponseMessage(req) {
			st.tokens.record()
			st.tokens = nil
		}
	}
}

// handle answers one ext_proc message. In FULL_DUPLEX_STREAMED mode the
// gateway does not wait for an answer per body chunk, so request chunks are
// held until the body ends and answered with one streamed body (or an
// immediate 403 or 413).
func (g *gatewayExt) handle(ctx context.Context, st *gatewayRequest, req *extprocv3.ProcessingRequest) ([]*extprocv3.ProcessingResponse, error) {
	switch r := req.Request.(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		for _, h := range r.RequestHeaders.GetHeaders().GetHeaders() {
			v := h.GetValue()
			if len(h.GetRawValue()) > 0 {
				v = string(h.GetRawValue())
			}
			switch strings.ToLower(h.GetKey()) {
			case ":authority", "host":
				if st.host == "" {
					st.host = v
				}
			case ":path":
				st.path = strings.TrimPrefix(v, "/")
			default:
				st.hdr.Add(h.GetKey(), v)
			}
		}
		if st.host == "" {
			return nil, status.Error(codes.InvalidArgument, "request headers carry no :authority")
		}
		// Our hint headers never travel upstream, as with the proxy.
		hdrResp := &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{
				HeaderMutation: &extprocv3.HeaderMutation{RemoveHeaders: []string{
					strings.ToLower(headerLabels), strings.ToLower(headerAgent), strings.ToLower(headerCredential)}},
			}}}}
		if r.RequestHeaders.GetEndOfStream() {
			// No body: decide on the headers alone.
			if deny := g.decide(ctx, st); deny != nil {
				return []*extprocv3.ProcessingResponse{deny}, nil
			}
		}
		return []*extprocv3.ProcessingResponse{hdrResp}, nil

	case *extprocv3.ProcessingRequest_RequestBody:
		chunk := r.RequestBody.GetBody()
		if !st.tooBig && int64(len(st.body)+len(chunk)) > g.p.maxBody {
			st.tooBig, st.body = true, nil
		}
		if !st.tooBig {
			st.body = append(st.body, chunk...)
		}
		if !r.RequestBody.GetEndOfStream() {
			return nil, nil
		}
		return g.finishRequest(ctx, st, true), nil

	case *extprocv3.ProcessingRequest_RequestTrailers:
		var out []*extprocv3.ProcessingResponse
		if !st.done {
			out = g.finishRequest(ctx, st, false)
			if len(out) == 1 && out[0].GetImmediateResponse() != nil {
				return out, nil
			}
		}
		return append(out, &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &extprocv3.TrailersResponse{}}}), nil

	case *extprocv3.ProcessingRequest_ResponseHeaders:
		return []*extprocv3.ProcessingResponse{{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{}}}}, nil

	case *extprocv3.ProcessingRequest_ResponseBody:
		chunk := r.ResponseBody.GetBody()
		if st.tokens != nil {
			st.tokens.Write(chunk)
		}
		return []*extprocv3.ProcessingResponse{{Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: streamedBody(chunk, r.ResponseBody.GetEndOfStream())}}}, nil

	case *extprocv3.ProcessingRequest_ResponseTrailers:
		return []*extprocv3.ProcessingResponse{{Response: &extprocv3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &extprocv3.TrailersResponse{}}}}, nil
	}
	return nil, status.Error(codes.InvalidArgument, "unknown ext_proc message")
}

// finishRequest decides once the request body is complete and either denies
// the request or hands the body back to the gateway unchanged.
func (g *gatewayExt) finishRequest(ctx context.Context, st *gatewayRequest, endOfStream bool) []*extprocv3.ProcessingResponse {
	st.done = true
	if st.tooBig {
		// 413 in every mode, as in the proxy: an unscanned forward is a blind spot.
		return []*extprocv3.ProcessingResponse{immediate(st.host, http.StatusRequestEntityTooLarge, "request_too_large",
			fmt.Sprintf("swarmsheriff: request body over the %d byte scan limit", g.p.maxBody))}
	}
	if deny := g.decide(ctx, st); deny != nil {
		return []*extprocv3.ProcessingResponse{deny}
	}
	body := st.body
	st.body = nil // dropped as soon as it is handed back
	return []*extprocv3.ProcessingResponse{{Response: &extprocv3.ProcessingResponse_RequestBody{
		RequestBody: streamedBody(body, endOfStream)}}}
}

// decide runs the shared pipeline and returns an immediate response to deny
// the request, or nil to let it through.
func (g *gatewayExt) decide(ctx context.Context, st *gatewayRequest) *extprocv3.ProcessingResponse {
	st.done = true
	rl := g.p.judge(ctx, st.host, st.path, st.hdr, st.body)
	if rl.status != 0 {
		st.body = nil
		return immediate(st.host, rl.status, rl.typ, rl.msg)
	}
	st.tokens = &tokenCapture{rec: g.p.rec, model: rl.model, provider: rl.d.Destination,
		dest: rl.d.Destination, agentID: rl.d.AgentID}
	return nil
}

func streamedBody(b []byte, end bool) *extprocv3.BodyResponse {
	return &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{BodyMutation: &extprocv3.BodyMutation{
		Mutation: &extprocv3.BodyMutation_StreamedResponse{StreamedResponse: &extprocv3.StreamedBodyResponse{
			Body: b, EndOfStream: end}}}}}
}

func immediate(host string, code int, typ, msg string) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			Status: &typev3.HttpStatus{Code: typev3.StatusCode(code)},
			Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{{
				Header: &corev3.HeaderValue{Key: "content-type", RawValue: []byte("application/json")}}}},
			Body:    errorBody(host, code, typ, msg),
			Details: "swarmsheriff_" + typ,
		}}}
}

func isLastResponseMessage(req *extprocv3.ProcessingRequest) bool {
	switch r := req.Request.(type) {
	case *extprocv3.ProcessingRequest_ResponseBody:
		return r.ResponseBody.GetEndOfStream()
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		return r.ResponseHeaders.GetEndOfStream()
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		return true
	}
	return false
}

// startGateway serves the extension until ctx is cancelled. TLS is required:
// Agent Gateway reaches extensions over HTTP/2 with TLS on port 443.
func startGateway(ctx context.Context, addr, certFile, keyFile string, p *llmProxy) error {
	if certFile == "" || keyFile == "" {
		return errors.New("-gateway-listen needs -gateway-cert and -gateway-key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("gateway certificate: %w", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})))
	extprocv3.RegisterExternalProcessorServer(srv, &gatewayExt{p: p})
	p.logger.Info("gateway extension listening", "addr", addr)

	go func() {
		<-ctx.Done()
		done := make(chan struct{})
		go func() { srv.GracefulStop(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			srv.Stop()
		}
	}()
	return srv.Serve(ln)
}
