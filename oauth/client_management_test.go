package oauth

import (
	"path/filepath"
	"testing"
)

func TestOAuthClientManagementRevokesGrantsOnUpdateAndDelete(t *testing.T) {
	service, err := New(filepath.Join(t.TempDir(), "oauth.json"))
	if err != nil {
		t.Fatal(err)
	}

	alpha, err := service.RegisterClient(ClientMetadata{
		ClientName:   "Alpha",
		RedirectURIs: []string{"https://client.example/alpha"},
	})
	if err != nil {
		t.Fatal(err)
	}
	beta, err := service.RegisterClient(ClientMetadata{
		ClientName:   "Beta",
		RedirectURIs: []string{"https://client.example/beta"},
	})
	if err != nil {
		t.Fatal(err)
	}

	clients, err := service.ListClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 || clients[0].ID != alpha.ID || clients[1].ID != beta.ID {
		t.Fatalf("unexpected client list: %#v", clients)
	}

	verifier := "oauth-client-management-verifier-long-enough-123456"
	code, err := service.Approve(AuthorizationRequest{
		UserID: "usr_admin", ClientID: alpha.ID,
		RedirectURI: alpha.RedirectURIs[0], Resource: "https://mcp.example.test/mcp/demo",
		Scope: "mcp:*", CodeChallenge: PKCEChallengeS256(verifier), CodeChallengeMethod: CodeChallengeMethodS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	set, err := service.ExchangeCode(alpha.ID, code, alpha.RedirectURIs[0], "https://mcp.example.test/mcp/demo", verifier)
	if err != nil {
		t.Fatal(err)
	}

	pendingCode, err := service.Approve(AuthorizationRequest{
		UserID: "usr_admin", ClientID: alpha.ID,
		RedirectURI: alpha.RedirectURIs[0], Resource: "https://mcp.example.test/mcp/demo",
		Scope: "mcp:*", CodeChallenge: PKCEChallengeS256(verifier), CodeChallengeMethod: CodeChallengeMethodS256,
	})
	if err != nil {
		t.Fatal(err)
	}

	updated, err := service.UpdateClient(alpha.ID, ClientMetadata{
		ClientName:   "Alpha Updated",
		RedirectURIs: []string{"https://client.example/new-alpha"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != alpha.ID || updated.ClientName != "Alpha Updated" || updated.CreatedAt != alpha.CreatedAt {
		t.Fatalf("unexpected updated client: %#v", updated)
	}
	if _, err := service.ValidateAccessToken(set.AccessToken); err == nil {
		t.Fatal("client update should revoke existing access token")
	}
	if _, err := service.ExchangeCode(alpha.ID, pendingCode, alpha.RedirectURIs[0], "https://mcp.example.test/mcp/demo", verifier); err == nil {
		t.Fatal("client update should revoke pending authorization code")
	}

	newVerifier := "oauth-client-delete-verifier-long-enough-12345678"
	newCode, err := service.Approve(AuthorizationRequest{
		UserID: "usr_admin", ClientID: alpha.ID,
		RedirectURI: updated.RedirectURIs[0], Resource: "https://mcp.example.test/mcp/demo",
		Scope: "mcp:*", CodeChallenge: PKCEChallengeS256(newVerifier), CodeChallengeMethod: CodeChallengeMethodS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	newSet, err := service.ExchangeCode(alpha.ID, newCode, updated.RedirectURIs[0], "https://mcp.example.test/mcp/demo", newVerifier)
	if err != nil {
		t.Fatal(err)
	}

	if err := service.DeleteClient(alpha.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetClient(alpha.ID); err == nil {
		t.Fatal("deleted client should not be found")
	}
	if _, err := service.ValidateAccessToken(newSet.AccessToken); err == nil {
		t.Fatal("client delete should revoke existing access token")
	}

	clients, err = service.ListClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].ID != beta.ID {
		t.Fatalf("unexpected clients after delete: %#v", clients)
	}
}

func TestOAuthClientManagementValidatesMetadata(t *testing.T) {
	service, err := New(filepath.Join(t.TempDir(), "oauth.json"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := service.RegisterClient(ClientMetadata{
		ClientName:   "Client",
		RedirectURIs: []string{"https://client.example/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateClient(client.ID, ClientMetadata{
		ClientName:   "Invalid",
		RedirectURIs: []string{"http://example.com/callback"},
	}); err == nil {
		t.Fatal("expected redirect URI validation error")
	}
	got, err := service.GetClient(client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientName != "Client" || got.RedirectURIs[0] != "https://client.example/callback" {
		t.Fatalf("failed update should not mutate client: %#v", got)
	}
}
