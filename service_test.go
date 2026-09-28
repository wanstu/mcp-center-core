package mcpcenter

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFileStoreAndCRUD(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := New(store)
	added, err := service.Add(Config{Name: "demo", Endpoint: "http://127.0.0.1:9000/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if added.ID == "" || added.Transport != TransportStreamableHTTP || added.AuthMode != AuthNone {
		t.Fatalf("unexpected added definition: %#v", added)
	}
	items, err := service.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("list: %#v %v", items, err)
	}
	added.Name = "changed"
	updated, err := service.Update(added.ID, Config{Name: added.Name, Endpoint: "https://example.test/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "changed" {
		t.Fatalf("update failed: %#v", updated)
	}
	if err := service.Remove(added.ID); err != nil {
		t.Fatal(err)
	}
	items, err = service.List()
	if err != nil || len(items) != 0 {
		t.Fatalf("expected empty list: %#v %v", items, err)
	}
}

func TestDisabledMCPRejectsActivationAndCanBeReenabled(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := New(store)
	added, err := service.Add(Config{
		Name: "disabled-demo", Endpoint: "http://127.0.0.1:9000/mcp", Disabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !added.Disabled {
		t.Fatalf("disabled state was not persisted: %#v", added)
	}
	if _, err := service.Resolve(added.ID); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled activation error, got %v", err)
	}
	updated, err := service.SetDisabled(added.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Disabled {
		t.Fatalf("MCP should be enabled after update: %#v", updated)
	}
	activation, err := service.Resolve(added.ID)
	if err != nil {
		t.Fatal(err)
	}
	if activation.Endpoint != "http://127.0.0.1:9000/mcp" {
		t.Fatalf("unexpected activation: %#v", activation)
	}
}

func TestGetByRefSupportsIDAndNameWithIDPriority(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := New(store)
	first, err := service.Add(Config{Name: "wm_test_db", Endpoint: "http://127.0.0.1:9000/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Add(Config{Name: first.ID, Endpoint: "http://127.0.0.1:9001/mcp"})
	if err != nil {
		t.Fatal(err)
	}

	byID, err := service.GetByRef(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if byID.ID != first.ID {
		t.Fatalf("ID lookup should win over name collision: %#v", byID)
	}

	byName, err := service.GetByRef("WM_TEST_DB")
	if err != nil {
		t.Fatal(err)
	}
	if byName.ID != first.ID {
		t.Fatalf("name lookup = %#v, want %#v", byName, first)
	}

	bySecondID, err := service.GetByRef(second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bySecondID.ID != second.ID {
		t.Fatalf("second ID lookup = %#v", bySecondID)
	}

	if _, err := service.GetByRef("missing"); err == nil {
		t.Fatal("expected missing reference error")
	}
}

func TestValidateSecretReferences(t *testing.T) {
	_, err := Validate(Config{
		Name: "secure", Transport: TransportStreamableHTTP, AuthMode: AuthHeaders,
		Endpoint: "https://example.test/mcp", HeaderRefs: map[string]string{"Authorization": "Bearer plain"},
	})
	if err == nil {
		t.Fatal("expected literal header rejection")
	}
	def, err := Validate(Config{
		Name: "secure", Transport: TransportStreamableHTTP, AuthMode: AuthHeaders,
		Endpoint: "https://example.test/mcp", HeaderRefs: map[string]string{"Authorization": "Bearer ${TOKEN}"},
	})
	if err != nil || def.AuthMode != AuthHeaders {
		t.Fatalf("expected valid secure config: %#v %v", def, err)
	}
}
