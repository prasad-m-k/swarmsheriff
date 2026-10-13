// Command swarmsheriff watches the clipboard, running AI apps and AI sites in
// Chrome, and, with -proxy or -gateway-listen, decides whether requests to LLM
// APIs may carry company data. This file holds the flags and the wiring.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"swarmsheriff/internal/classify"
	"swarmsheriff/internal/clipboard"
	"swarmsheriff/internal/dashboard"
	"swarmsheriff/internal/decide"
	"swarmsheriff/internal/dlp"
	"swarmsheriff/internal/eval"
	"swarmsheriff/internal/events"
	"swarmsheriff/internal/hooks"
	"swarmsheriff/internal/intake"
	"swarmsheriff/internal/logfile"
	"swarmsheriff/internal/metrics"
	"swarmsheriff/internal/policy"
	"swarmsheriff/internal/proxy"
	"swarmsheriff/internal/sentinel"
	"swarmsheriff/internal/watch"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "metrics" {
		os.Exit(metrics.RunCLI(os.Args[2:], os.Stdout, os.Stderr, time.Now()))
	}
	if len(os.Args) > 1 && os.Args[1] == "dashboard" {
		os.Exit(dashboard.RunCLI(os.Args[2:], os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "hook" {
		rest := os.Args[2:]
		// Custom agents are defined as JSON in the adapters directory.
		adaptersDir := hooks.DefaultAdaptersDir()
		for i := 0; i < len(rest)-1; i++ {
			if rest[i] == "--adapters" {
				adaptersDir = rest[i+1]
			}
		}
		if slices.Contains(rest, "--list-agents") {
			for _, err := range hooks.LoadCustomAdapters(adaptersDir) {
				fmt.Fprintln(os.Stderr, "adapter warning:", err)
			}
			fmt.Println("agents swarmsheriff can hook (built-in + adapters in " + adaptersDir + "):")
			for _, name := range hooks.KnownAgents() {
				style := "built-in"
				if a := hooks.CustomAdapters[name]; a != nil {
					style = "custom (" + a.ConfigStyle + ")"
				}
				fmt.Printf("  %-16s %s\n", name, style)
			}
			return
		}
		if pc := slices.Index(rest, "--print-config"); pc >= 0 {
			exe, err := os.Executable()
			if err != nil {
				exe = "swarmsheriff"
			}
			agent := hooks.AgentKindClaude
			if pc+1 < len(rest) && !strings.HasPrefix(rest[pc+1], "-") {
				agent = rest[pc+1]
			}
			if !hooks.IsBuiltinAgent(agent) {
				for _, e := range hooks.LoadCustomAdapters(adaptersDir) {
					fmt.Fprintln(os.Stderr, "adapter warning:", e)
				}
			}
			out, err := hooks.Snippet(agent, exe)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(2)
			}
			fmt.Fprintln(os.Stderr, hooks.ConfigDest(agent))
			fmt.Println(out)
			return
		}
		os.Exit(hooks.RunCLI(rest, os.Stdin, time.Now()))
	}
	interval := flag.Duration("interval", 500*time.Millisecond, "how often to poll the clipboard")
	once := flag.Bool("once", false, "print the current clipboard to stdout and exit")
	logPath := flag.String("log", "swarmsheriff.log", "log file path")
	maxMB := flag.Float64("max-mb", 10, "rotate after the log reaches this many MB (0 = no size limit)")
	maxLines := flag.Int64("max-lines", 10000, "rotate after the log reaches this many lines (0 = no line limit)")
	maxBackups := flag.Int("max-backups", 5, "number of rotated files to keep")
	quiet := flag.Bool("quiet", false, "write to the log file only, not the console")
	aiInterval := flag.Duration("ai-interval", 5*time.Second, "how often to scan for AI/LLM apps (0 = disabled)")
	watchBrowser := flag.Bool("browser", true, "also log AI sites open in Chrome tabs (macOS only)")
	logContent := flag.Bool("log-content", true, "log captured clipboard text; false = log DLP findings only, never the raw content")
	keywords := flag.String("dlp-keywords", "", "comma-separated confidential markers to flag (e.g. a project codename)")
	listen := flag.String("listen", "", "loopback address for the DLP scan endpoint, e.g. 127.0.0.1:8787 (empty = disabled)")
	intakeToken := flag.String("intake-token", "", "bearer token required by the scan endpoint (generated if empty)")
	policyPath := flag.String("policy", "", "company data policy file, JSON (required by -proxy and -eval)")
	proxyAddr := flag.String("proxy", "", "loopback address for the LLM reverse proxy, e.g. 127.0.0.1:8788 (empty = disabled)")
	proxyMaxMB := flag.Float64("proxy-max-mb", 32, "largest request body the proxy will scan and forward, in MB")
	mode := flag.String("mode", "", "report or enforce; overrides the policy's global mode (per-class modes still win)")
	evalDir := flag.String("eval", "", "score the policy against a labeled corpus directory, print the results, and exit")
	classifierName := flag.String("classifier", "none", "classifier for ambiguous text: none or jev (jev reads OPENROUTER_API_KEY)")
	classifierModel := flag.String("classifier-model", classify.JevDefaultModel, "pinned classifier model ID")
	classifierTimeout := flag.Duration("classifier-timeout", 2*time.Second, "longest the classifier may hold up a request")
	guardMode := flag.String("clipboard-guard", clipboard.GuardOff, "replace a sensitive clipboard with a notice: off, ai (while an AI site or desktop AI app is open), or always")
	guardRules := flag.String("guard-rules", clipboard.DefaultGuardRules, "DLP rules that trigger the clipboard guard; keyword:* means every -dlp-keywords marker")
	metricsOn := flag.Bool("metrics", true, "record body-free metrics in a local SQLite database (read with: swarmsheriff metrics query)")
	metricsPath := flag.String("metrics-db", metrics.DefaultPath(), "metrics database path")
	metricsRetention := flag.Duration("metrics-retention", 30*24*time.Hour, "how long metrics are kept before pruning (0 = keep until the size cap)")
	metricsMaxMB := flag.Int64("metrics-max-mb", 256, "size cap for the metrics database, in MB")
	hooksOn := flag.Bool("hooks", true, "accept agent lifecycle events from \"swarmsheriff hook\" on a private Unix socket (needs -metrics)")
	hookSocket := flag.String("hook-socket", hooks.DefaultSocket(), "Unix socket for agent lifecycle hooks")
	sentinelURL := flag.String("sentinel", "", "SwarmSentinel engine URL for engine-issued agent identity, confidentiality labels and the decision feed (empty = off)")
	sentinelSecret := flag.String("sentinel-secret-file", "", "file holding the shared secret for the SwarmSentinel egress endpoints (required with -sentinel)")
	gatewayAddr := flag.String("gateway-listen", "", "address for the Google Agent Gateway authorization extension (ext_proc over TLS), e.g. 10.0.0.5:443; not loopback-only (empty = disabled)")
	gatewayCert := flag.String("gateway-cert", "", "TLS certificate file for -gateway-listen")
	gatewayKey := flag.String("gateway-key", "", "TLS private key file for -gateway-listen")
	requireCredential := flag.Bool("require-credential", false, "refuse proxy requests without an engine-issued agent credential (needs -sentinel)")
	dashboardAddr := flag.String("dashboard", "127.0.0.1:9090", "serve the metrics dashboard on this loopback address (empty = off; needs -metrics)")
	flag.Parse()

	scanner := dlp.NewScanner(strings.Split(*keywords, ","))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *mode != "" && *mode != policy.ModeReport && *mode != policy.ModeEnforce {
		fmt.Fprintf(os.Stderr, "error: -mode %q is not report or enforce\n", *mode)
		os.Exit(2)
	}
	guard, err := clipboard.NewGuard(*guardMode, *guardRules)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if guard.Mode == clipboard.GuardAI && *aiInterval <= 0 {
		fmt.Fprintln(os.Stderr, "error: -clipboard-guard ai needs -ai-interval > 0 to know when AI tools are open")
		os.Exit(2)
	}
	if (*proxyAddr != "" || *evalDir != "" || *gatewayAddr != "") && *policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: -proxy, -gateway-listen and -eval need -policy")
		os.Exit(2)
	}
	if *gatewayAddr != "" && (*gatewayCert == "" || *gatewayKey == "") {
		fmt.Fprintln(os.Stderr, "error: -gateway-listen needs -gateway-cert and -gateway-key")
		os.Exit(2)
	}
	var dec *decide.Decider
	if *policyPath != "" {
		// An invalid policy at startup is fatal; only reloads fall back.
		pol, err := policy.Load(*policyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		clf, err := newClassifier(*classifierName, *classifierModel)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
		dec = decide.New(pol, clf, *classifierTimeout, *mode)
	}

	if *evalDir != "" {
		samples, err := eval.LoadCorpus(*evalDir)
		if err == nil {
			dec.Exhaustive = true
			err = eval.Run(ctx, dec, samples, os.Stdout)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: eval:", err)
			os.Exit(1)
		}
		return
	}

	if *once {
		data, err := clipboard.ReadClipboard(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		os.Stdout.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			fmt.Println()
		}
		return
	}

	logFile, err := logfile.Open(*logPath, int64(*maxMB*1024*1024), *maxLines, *maxBackups)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: open log:", err)
		os.Exit(1)
	}
	defer logFile.Close()

	var out io.Writer = logFile
	if !*quiet {
		out = io.MultiWriter(logFile, os.Stdout)
	}
	// logfmt lines: one entry per line, with newlines and control characters
	// in the clipboard text escaped inside the quoted text= value.
	logger := slog.New(slog.NewTextHandler(out, nil))

	// Fail fast if no clipboard tool is usable at all; after this, read
	// errors are logged and polling continues.
	last, err := clipboard.ReadClipboard(ctx)
	if err != nil {
		logger.Error("clipboard unavailable", "err", err)
		os.Exit(1)
	}
	var rec metrics.Recorder = metrics.NopRecorder{}
	var store *metrics.Store
	if *metricsOn {
		store, err = metrics.OpenStore(*metricsPath, *metricsRetention, *metricsMaxMB*1024*1024, logger)
		if err != nil {
			logger.Error("metrics unavailable", "err", err)
			os.Exit(1)
		}
		rec = store
		defer store.Close()
	}
	rec.Record(metrics.Event{Kind: metrics.KindAgentStarted})

	startAttrs := []any{"interval", *interval, "log", *logPath,
		"max_mb", *maxMB, "max_lines", *maxLines, "max_backups", *maxBackups, "ai_interval", *aiInterval,
		"clipboard_guard", guard.Mode}
	if dec != nil {
		pol := dec.Policy.Load()
		startAttrs = append(startAttrs, "policy", *policyPath, "proxy", *proxyAddr, "proxy_max_mb", *proxyMaxMB,
			"mode", dec.ModeFor(pol, nil), "classifier", dec.Classifier.Name(), "classifier_timeout", *classifierTimeout)
		// The secret file path is logged; the secret itself never is.
		startAttrs = append(startAttrs, "sentinel", *sentinelURL, "require_credential", *requireCredential,
			"gateway_listen", *gatewayAddr)
		// Raw content to a hosted classifier is an explicit policy choice; make it visible.
		if raw := pol.RawClassifierClasses(); len(raw) > 0 && *classifierName != "none" {
			startAttrs = append(startAttrs, "classifier_raw", strings.Join(raw, ","))
		}
	}
	if store != nil {
		startAttrs = append(startAttrs, "metrics_db", *metricsPath, "metrics_retention", *metricsRetention)
		if *hooksOn {
			startAttrs = append(startAttrs, "hook_socket", *hookSocket)
		}
		if *dashboardAddr != "" {
			startAttrs = append(startAttrs, "dashboard", *dashboardAddr)
		}
	}
	logger.Info("swarmsheriff started", startAttrs...)

	intakeErrCh := make(chan error, 2)
	if *listen != "" {
		token := *intakeToken
		if token == "" {
			token = intake.NewToken()
			// Printed to stderr, never the log file, so the token is not
			// persisted alongside the data it protects.
			fmt.Fprintf(os.Stderr, "swarmsheriff: intake token: %s\n", token)
		}
		go func() {
			if err := intake.Start(ctx, *listen, token, logger, scanner, *logContent, rec); err != nil {
				logger.Error("intake endpoint failed", "err", err)
				intakeErrCh <- err
				stop() // a requested endpoint that cannot start ends the program
			}
		}()
	}
	if store != nil && *hooksOn {
		go func() {
			if err := hooks.StartServer(ctx, *hookSocket, rec, logger); err != nil {
				// Lifecycle metrics are optional; the rest of swarmsheriff keeps running.
				logger.Error("hook socket failed", "err", err)
			}
		}()
	}
	if store != nil && *dashboardAddr != "" {
		// Reads the same database read-only; WAL mode allows it alongside the
		// writer. A bind failure is logged but does not stop collection.
		go func() {
			if err := dashboard.Start(ctx, *dashboardAddr, *metricsPath, metrics.DefaultStallMs, logger); err != nil {
				logger.Error("dashboard failed", "err", err)
			}
		}()
	}
	if *proxyAddr != "" || *gatewayAddr != "" {
		var sink events.Sink = events.LogSink{Logger: logger}
		var sentinelClient *sentinel.Client
		if *sentinelURL != "" {
			c, err := sentinel.NewClient(*sentinelURL, *sentinelSecret)
			if err != nil {
				fmt.Fprintln(os.Stderr, "swarmsheriff:", err)
				os.Exit(2)
			}
			sentinelClient = c
			sink = sentinel.MultiSink{sink, sentinel.NewSink(ctx, c, logger)}
		} else if *requireCredential {
			fmt.Fprintln(os.Stderr, "swarmsheriff: -require-credential needs -sentinel")
			os.Exit(2)
		}
		p := proxy.New(dec, sink, logger, int64(*proxyMaxMB*1024*1024))
		p.Sentinel, p.RequireCredential = sentinelClient, *requireCredential
		p.Rec = rec
		if *proxyAddr != "" {
			go func() {
				if err := proxy.Start(ctx, *proxyAddr, p); err != nil {
					logger.Error("proxy failed", "err", err)
					select {
					case intakeErrCh <- err:
					default:
					}
					stop()
				}
			}()
		}
		if *gatewayAddr != "" {
			go func() {
				if err := proxy.StartGateway(ctx, *gatewayAddr, *gatewayCert, *gatewayKey, p); err != nil {
					logger.Error("gateway extension failed", "err", err)
					select {
					case intakeErrCh <- err:
					default:
					}
					stop()
				}
			}()
		}
	}
	var policyTick <-chan time.Time
	var policyMod time.Time
	var lastPolicyErr string
	if dec != nil {
		if fi, err := os.Stat(*policyPath); err == nil {
			policyMod = fi.ModTime()
		}
		t := time.NewTicker(policyReloadInterval)
		defer t.Stop()
		policyTick = t.C
	}

	var aiTick <-chan time.Time
	var ai *watch.AIWatcher
	var browser *watch.BrowserWatcher
	var lastAIErr, lastBrowserErr string
	if *aiInterval > 0 {
		ai = watch.NewAIWatcher(logger)
		ai.Rec = rec
		if err := ai.Scan(ctx, true); err != nil {
			logger.Error("process scan failed", "err", err)
			lastAIErr = err.Error()
		}
		if *watchBrowser {
			browser = watch.NewBrowserWatcher(logger)
			browser.Rec = rec
			if err := browser.Scan(ctx, true); err != nil {
				logger.Error("browser scan failed", "err", err)
				lastBrowserErr = err.Error()
			}
		}
		t := time.NewTicker(*aiInterval)
		defer t.Stop()
		aiTick = t.C
	}

	aiContext := func() bool {
		return (browser != nil && browser.AnyOpen()) || (ai != nil && ai.AnyDesktop())
	}
	// handleClipboard logs a new clipboard value, or guards it, and returns
	// what the clipboard now holds.
	handleClipboard := func(data []byte) []byte {
		findings := scanner.Scan(string(data))
		hit := guard.Trigger(findings, aiContext())
		if len(hit) == 0 {
			logClipboard(logger, scanner, *logContent, data)
			rec.Record(metrics.Event{Kind: metrics.KindClipboard, Bytes: len(data), Rules: findings})
			return data
		}
		notice := []byte(clipboard.GuardNotice(hit))
		if err := clipboard.WriteClipboard(ctx, notice); err != nil {
			logger.Error("clipboard guard failed", "err", err, "dlp", dlp.Summary(hit))
			logClipboard(logger, scanner, *logContent, data)
			rec.Record(metrics.Event{Kind: metrics.KindClipboard, Bytes: len(data), Rules: findings})
			return data
		}
		// The guarded text is never logged, whatever -log-content says: the
		// guard exists to keep it from going anywhere.
		logger.Warn("clipboard guarded", "bytes", len(data), "dlp", dlp.Summary(hit), "mode", guard.Mode)
		rec.Record(metrics.Event{Kind: metrics.KindClipboardGuard, Bytes: len(data), Rules: hit, Mode: guard.Mode})
		return notice
	}
	if len(last) > 0 {
		last = handleClipboard(last)
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			logger.Info("swarmsheriff stopped")
			rec.Record(metrics.Event{Kind: metrics.KindAgentStopped})
			select {
			case <-intakeErrCh:
				if store != nil {
					store.Close() // os.Exit skips deferred calls
				}
				os.Exit(1) // the intake endpoint or proxy failed to start
			default:
			}
			return
		case <-policyTick:
			fi, err := os.Stat(*policyPath)
			if err == nil && fi.ModTime().Equal(policyMod) {
				continue
			}
			var pol *policy.Policy
			if err == nil {
				pol, err = policy.Load(*policyPath)
			}
			if err != nil {
				// Keep the last good policy; log each distinct problem once.
				if err.Error() != lastPolicyErr {
					logger.Error("policy reload failed, keeping last good policy", "err", err)
					lastPolicyErr = err.Error()
				}
				continue
			}
			policyMod, lastPolicyErr = fi.ModTime(), ""
			dec.Policy.Store(pol)
			logger.Info("policy reloaded", "policy", *policyPath, "classes", len(pol.Classes))
			rec.Record(metrics.Event{Kind: metrics.KindPolicyReload})
			continue
		case <-aiTick:
			if err := ai.Scan(ctx, false); err != nil {
				if ctx.Err() == nil && err.Error() != lastAIErr {
					logger.Error("process scan failed", "err", err)
					lastAIErr = err.Error()
				}
			} else {
				lastAIErr = ""
			}
			if browser != nil {
				if err := browser.Scan(ctx, false); err != nil {
					if ctx.Err() == nil && err.Error() != lastBrowserErr {
						logger.Error("browser scan failed", "err", err)
						lastBrowserErr = err.Error()
					}
				} else {
					lastBrowserErr = ""
				}
			}
			continue
		case <-ticker.C:
		}

		data, err := clipboard.ReadClipboard(ctx)
		if err != nil {
			if ctx.Err() != nil {
				continue // shutting down; the select above will exit
			}
			// Log each distinct error once rather than on every tick.
			if err.Error() != lastErr {
				logger.Error("clipboard read failed", "err", err)
				lastErr = err.Error()
			}
			continue
		}
		lastErr = ""
		if len(data) > 0 && !bytes.Equal(data, last) {
			last = handleClipboard(data)
		}
	}
}

// policyReloadInterval is how often the policy file is checked for changes.
const policyReloadInterval = 5 * time.Second

func newClassifier(name, model string) (classify.Classifier, error) {
	switch name {
	case "none", "":
		return classify.Noop{}, nil
	case "jev":
		key := os.Getenv("OPENROUTER_API_KEY")
		if key == "" {
			return nil, errors.New("-classifier jev needs OPENROUTER_API_KEY in the environment")
		}
		return classify.NewJev(model, key), nil
	default:
		return nil, fmt.Errorf("-classifier %q is not none or jev", name)
	}
}

// logClipboard records a clipboard capture. It scans for confidential data
// first; when anything matches, the entry is logged at WARN with a dlp= field.
// With logContent false the raw text is never written, only the findings, so
// the log does not become a store of the data it is meant to protect.
func logClipboard(logger *slog.Logger, scanner *dlp.Scanner, logContent bool, data []byte) {
	findings := scanner.Scan(string(data))
	attrs := []any{"bytes", len(data)}
	if len(findings) > 0 {
		attrs = append(attrs, "dlp", dlp.Summary(findings))
	}
	if logContent {
		attrs = append(attrs, "text", string(data))
	}
	if len(findings) > 0 {
		logger.Warn("clipboard", attrs...)
	} else {
		logger.Info("clipboard", attrs...)
	}
}
