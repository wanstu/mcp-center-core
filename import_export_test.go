package mcpcenter

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func newImportExportService(t *testing.T) *Service {
	t.Helper()
	store, err := NewFileStore(filepath.Join(t.TempDir(), "mcps.json"))
	if err != nil {
		t.Fatal(err)
	}
	return New(store)
}

func TestImportGenericMCPServersAndExport(t *testing.T) {
	svc := newImportExportService(t)
	input := []byte("{\"mcpServers\":{\"remote\":{\"url\":\"https://example.com/mcp\",\"headers\":{\"Authorization\":\"Bearer ${REMOTE_TOKEN}\"}},\"local\":{\"command\":\"node\",\"args\":[\"server.js\",\"--stdio\"],\"env\":{\"API_KEY\":\"${LOCAL_API_KEY}\"}}}}")

	result, err := svc.ImportJSON(input, ImportFormatAuto, ConflictError)
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 2 || result.Updated != 0 || result.Skipped != 0 {
		t.Fatalf("unexpected import result: %#v", result)
	}

	items, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("len = %d, want 2", len(items))
	}
	byName := map[string]Definition{}
	for _, item := range items {
		byName[item.Name] = item
	}
	if got := byName["remote"]; got.Transport != TransportStreamableHTTP || got.AuthMode != AuthHeaders || got.HeaderRefs["Authorization"] != "Bearer ${REMOTE_TOKEN}" {
		t.Fatalf("unexpected remote: %#v", got)
	}
	if got := byName["local"]; got.Transport != TransportStdio || got.Executable != "node" || len(got.Args) != 2 || got.EnvRefs["API_KEY"] != "${LOCAL_API_KEY}" {
		t.Fatalf("unexpected local: %#v", got)
	}

	exported, err := svc.ExportJSON(ImportFormatMCPServers)
	if err != nil {
		t.Fatal(err)
	}
	var generic genericBundle
	if err := json.Unmarshal(exported, &generic); err != nil {
		t.Fatal(err)
	}
	if len(generic.MCPServers) != 2 || generic.MCPServers["remote"].URL != "https://example.com/mcp" || generic.MCPServers["local"].Command != "node" {
		t.Fatalf("unexpected generic export: %s", exported)
	}
}

func TestImportConflictPoliciesAreAtomic(t *testing.T) {
	svc := newImportExportService(t)
	existing, err := svc.Add(Config{
		Name:      "existing",
		Transport: TransportStreamableHTTP,
		AuthMode:  AuthNone,
		Endpoint:  "https://old.example.com/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("{\"version\":1,\"mcps\":[{\"name\":\"existing\",\"transport\":\"streamable-http\",\"auth_mode\":\"none\",\"endpoint\":\"https://new.example.com/mcp\",\"health_policy\":{}},{\"name\":\"new-one\",\"transport\":\"streamable-http\",\"auth_mode\":\"none\",\"endpoint\":\"https://new-one.example.com/mcp\",\"health_policy\":{}}]}")

	if _, err := svc.ImportJSON(input, ImportFormatCore, ConflictError); err == nil {
		t.Fatal("expected conflict error")
	}
	items, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Endpoint != "https://old.example.com/mcp" {
		t.Fatalf("error policy must be atomic: %#v", items)
	}

	skip, err := svc.ImportJSON(input, ImportFormatCore, ConflictSkip)
	if err != nil {
		t.Fatal(err)
	}
	if skip.Added != 1 || skip.Skipped != 1 {
		t.Fatalf("unexpected skip result: %#v", skip)
	}

	updateInput := []byte("{\"version\":1,\"mcps\":[{\"name\":\"existing\",\"transport\":\"streamable-http\",\"auth_mode\":\"none\",\"endpoint\":\"https://updated.example.com/mcp\",\"health_policy\":{}}]}")
	update, err := svc.ImportJSON(updateInput, ImportFormatCore, ConflictUpdateByName)
	if err != nil {
		t.Fatal(err)
	}
	if update.Updated != 1 || len(update.Items) != 1 || update.Items[0].ID != existing.ID {
		t.Fatalf("unexpected update result: %#v", update)
	}
	got, err := svc.Get(existing.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoint != "https://updated.example.com/mcp" || !got.CreatedAt.Equal(existing.CreatedAt) {
		t.Fatalf("update did not preserve identity: %#v", got)
	}
}

func TestCoreExportRoundTripAndNoRuntimeIDs(t *testing.T) {
	svc := newImportExportService(t)
	_, err := svc.Add(Config{
		Name:           "roundtrip",
		DefaultInclude: true,
		Disabled:       true,
		Transport:      TransportStdio,
		AuthMode:       AuthNone,
		Executable:     "python",
		Args:           []string{"-m", "server"},
		EnvRefs:        map[string]string{"TOKEN": "${TOKEN}"},
		HealthPolicy: HealthPolicy{
			HealthCheckEnabled:       true,
			CheckIntervalSeconds:     60,
			ProbeTimeoutSeconds:      5,
			AutoReconnect:            true,
			ReconnectIntervalSeconds: 10,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	exported, err := svc.ExportJSON(ImportFormatCore)
	if err != nil {
		t.Fatal(err)
	}
	text := string(exported)
	if strings.Contains(text, "\"id\"") || strings.Contains(text, "\"created_at\"") || strings.Contains(text, "\"updated_at\"") {
		t.Fatalf("portable export leaked runtime identity fields: %s", text)
	}

	other := newImportExportService(t)
	result, err := other.ImportJSON(exported, ImportFormatAuto, ConflictError)
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 1 {
		t.Fatalf("unexpected roundtrip result: %#v", result)
	}
	items, _ := other.List()
	if len(items) != 1 || !items[0].DefaultInclude || !items[0].Disabled || items[0].Executable != "python" || !items[0].HealthPolicy.AutoReconnect {
		t.Fatalf("roundtrip mismatch: %#v", items)
	}
}

func TestGenericImportRejectsLiteralSecrets(t *testing.T) {
	svc := newImportExportService(t)
	input := []byte("{\"mcpServers\":{\"unsafe\":{\"url\":\"https://example.com/mcp\",\"headers\":{\"Authorization\":\"Bearer plaintext-secret\"}}}}")
	_, err := svc.ImportJSON(input, ImportFormatAuto, ConflictError)
	if err == nil || !strings.Contains(err.Error(), "environment reference") {
		t.Fatalf("expected secret reference validation error, got %v", err)
	}
	items, listErr := svc.List()
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(items) != 0 {
		t.Fatalf("failed import must not mutate store: %#v", items)
	}
}

func TestImportRejectsDuplicateNamesCaseInsensitive(t *testing.T) {
	svc := newImportExportService(t)
	input := []byte("{\"version\":1,\"mcps\":[{\"name\":\"Alpha\",\"transport\":\"streamable-http\",\"auth_mode\":\"none\",\"endpoint\":\"https://a.example/mcp\",\"health_policy\":{}},{\"name\":\"alpha\",\"transport\":\"streamable-http\",\"auth_mode\":\"none\",\"endpoint\":\"https://b.example/mcp\",\"health_policy\":{}}]}")
	if _, err := svc.ImportJSON(input, ImportFormatCore, ConflictError); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate name error, got %v", err)
	}
}
