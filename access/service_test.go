package access

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsAndSettingsValidation(t *testing.T) {
	svc, err := New(filepath.Join(t.TempDir(), "access.json"))
	if err != nil {
		t.Fatal(err)
	}
	settings, err := svc.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.BearerEnabled || !settings.HeaderEnabled || settings.QueryEnabled {
		t.Fatalf("unexpected defaults: %#v", settings)
	}
	if settings.HeaderName != "X-MCP-Token" || settings.QueryName != "mcp_token" {
		t.Fatalf("unexpected names: %#v", settings)
	}
	settings.QueryEnabled = true
	settings.QueryName = "token"
	updated, err := svc.UpdateSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.QueryEnabled || updated.QueryName != "token" {
		t.Fatalf("unexpected update: %#v", updated)
	}
	settings.HeaderName = "Authorization"
	if _, err := svc.UpdateSettings(settings); err == nil {
		t.Fatal("expected reserved header error")
	}
}

func TestCredentialSecretIsOneTimeAndChannelsAreEnforced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	svc, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := svc.Create(CreateInput{
		Name: "ci-agent", Enabled: true,
		AllowBearer: true, AllowHeader: true, AllowQuery: false,
		Scopes: []string{"mcp:read", "mcp:call"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Secret, "mcp_") || created.Credential.SecretPrefix == "" {
		t.Fatalf("unexpected generated secret: %#v", created)
	}
	items, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != "ci-agent" {
		t.Fatalf("unexpected list: %#v", items)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), created.Secret) {
		t.Fatal("raw secret must never be persisted")
	}

	principal, err := svc.Verify(created.Secret, ChannelBearer)
	if err != nil {
		t.Fatal(err)
	}
	if principal.DisplayName != "ci-agent" || principal.AuthChannel != ChannelBearer || !ScopeContains(principal.Scopes, "mcp:call") {
		t.Fatalf("unexpected principal: %#v", principal)
	}
	if _, err := svc.Verify(created.Secret, ChannelHeader); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(created.Secret, ChannelQuery); err == nil {
		t.Fatal("query channel should be denied for this credential")
	}
}

func TestDisabledAndExpiredCredentialsAreRejected(t *testing.T) {
	svc, err := New(filepath.Join(t.TempDir(), "access.json"))
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Minute)
	created, err := svc.Create(CreateInput{
		Name: "expired", Enabled: true, AllowBearer: true, ExpiresAt: &expired,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(created.Secret, ChannelBearer); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}

	active, err := svc.Create(CreateInput{
		Name: "disabled", Enabled: false, AllowBearer: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(active.Secret, ChannelBearer); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled error, got %v", err)
	}
}

func TestUpdateAndDelete(t *testing.T) {
	svc, err := New(filepath.Join(t.TempDir(), "access.json"))
	if err != nil {
		t.Fatal(err)
	}
	created, err := svc.Create(CreateInput{
		Name: "client", Enabled: true, AllowBearer: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.Update(created.Credential.ID, UpdateInput{
		Name: "client-2", Enabled: true, AllowHeader: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "client-2" || updated.AllowBearer || !updated.AllowHeader {
		t.Fatalf("unexpected update: %#v", updated)
	}
	if _, err := svc.Verify(created.Secret, ChannelBearer); err == nil {
		t.Fatal("bearer should be denied after update")
	}
	if _, err := svc.Verify(created.Secret, ChannelHeader); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(created.Credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(created.Secret, ChannelHeader); err == nil {
		t.Fatal("deleted credential should not verify")
	}
}
