package mcpcenter

import (
	"path/filepath"
	"testing"
)

func TestSetVariableLookupResolvesDefinitionReferences(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "mcps.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc := New(store)
	def, err := svc.Add(Config{
		Name:      "secured",
		Transport: TransportStreamableHTTP,
		AuthMode:  AuthHeaders,
		Endpoint:  "https://example.com/mcp",
		HeaderRefs: map[string]string{
			"Authorization": "Bearer ${UPSTREAM_TOKEN}",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	svc.SetVariableLookup(func(name string) (string, bool) {
		if name == "UPSTREAM_TOKEN" {
			return "secret-value", true
		}
		return "", false
	})
	activation, err := svc.Resolve(def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := activation.Headers["Authorization"]; got != "Bearer secret-value" {
		t.Fatalf("Authorization = %q", got)
	}

	svc.SetVariableLookup(func(string) (string, bool) { return "", false })
	if _, err := svc.Resolve(def.ID); err == nil {
		t.Fatal("expected unresolved environment reference")
	}

	svc.SetVariableLookup(nil)
}
