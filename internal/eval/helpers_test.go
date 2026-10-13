package eval

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"swarmsheriff/internal/policy"
	"testing"
)

// testPolicyJSON is a small valid policy shared by the tests.
const testPolicyJSON = `{
  "version": 1,
  "mode": "report",
  "destinations": {
    "approved": ["api.company-llm.example"],
    "public": ["api.anthropic.com", "api.openai.com"]
  },
  "classes": [
    {
      "id": "code", "description": "Proprietary source code", "owner": "engineering",
      "detectors": {"source_labels": ["repo:core"], "path_globs": ["**/core-platform/**"], "keywords": ["ProjectX"]},
      "classifier": {"enabled": true, "block_at": 0.9, "hold_at": 0.5},
      "actions": {"approved": "allow", "public": "block"}
    },
    {
      "id": "creds", "description": "Access credentials", "owner": "security",
      "detectors": {"rules": ["aws-access-key", "re:\\bINTERNAL-[0-9]{4}\\b"]},
      "actions": {"approved": "block", "public": "block"},
      "mode": "enforce"
    },
    {
      "id": "customers", "description": "Customer records", "owner": "privacy",
      "detectors": {"fingerprints": ["FINGERPRINT"]},
      "classifier": {"enabled": true, "block_at": 0.95},
      "actions": {"approved": "allow", "public": "hold"}
    }
  ]
}`

func mustPolicy(t *testing.T, js string) *policy.Policy {
	t.Helper()
	p, err := policy.ParsePolicy([]byte(strings.ReplaceAll(js, "FINGERPRINT", sha256Hex(knownDocLine))))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

const knownDocLine = "Quarterly customer retention list, rows follow"
