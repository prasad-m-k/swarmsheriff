// Package llm names LLM providers and reads model names from request bodies
// and paths.
package llm

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"
)

// modelName allows the characters model IDs use, including "/" for
// provider-prefixed IDs such as "openai/gpt-4o" on OpenRouter.
var modelName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)

func CleanModel(v any) string {
	s, _ := v.(string)
	if !modelName.MatchString(s) {
		return ""
	}
	return s
}

// Provider names the LLM provider behind an upstream host; unknown hosts
// are reported as themselves.
func Provider(host string) string {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, p := range []struct{ suffix, name string }{
		{"anthropic.com", "anthropic"}, {"openai.com", "openai"}, {"openrouter.ai", "openrouter"},
		{"googleapis.com", "google"}, {"mistral.ai", "mistral"}, {"x.ai", "xai"},
		{"deepseek.com", "deepseek"}, {"groq.com", "groq"}, {"cohere.com", "cohere"},
		{"cohere.ai", "cohere"}, {"together.xyz", "together"}, {"fireworks.ai", "fireworks"},
		{"azure.com", "azure"},
	} {
		if host == p.suffix || strings.HasSuffix(host, "."+p.suffix) {
			return p.name
		}
	}
	return host
}

// RequestModel reads the top-level "model" field of an LLM request body. It
// is a name, not content, and is dropped unless it looks like one.
func RequestModel(body []byte) string {
	var v struct {
		Model any `json:"model"`
	}
	if json.Unmarshal(body, &v) != nil {
		return ""
	}
	return CleanModel(v.Model)
}

// pathModel reads the model from a Gemini or Vertex AI path such as
// v1beta/models/gemini-2.5-pro:streamGenerateContent.
var rePathModel = regexp.MustCompile(`(?:^|/)models/([^/:?]+):`)

func PathModel(path string) string {
	m := rePathModel.FindStringSubmatch(path)
	if m == nil {
		return ""
	}
	return CleanModel(m[1])
}
