package mcpcenter

import (
	"path/filepath"
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
