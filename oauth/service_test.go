package oauth

import (
	"path/filepath"
	"testing"
)

func TestAuthorizationCodePKCEAndRefresh(t *testing.T) {
	service, err := New(filepath.Join(t.TempDir(), "oauth.json"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := service.RegisterClient(ClientMetadata{
		ClientName:   "Test Client",
		RedirectURIs: []string{"http://127.0.0.1:18888/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "test-code-verifier-that-is-long-enough-for-pkce"
	code, err := service.Approve(AuthorizationRequest{
		UserID: "usr_admin", ClientID: client.ID,
		RedirectURI: client.RedirectURIs[0], Scope: "mcp:read mcp:manage",
		CodeChallenge: PKCEChallengeS256(verifier), CodeChallengeMethod: CodeChallengeMethodS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	set, err := service.ExchangeCode(client.ID, code, client.RedirectURIs[0], verifier)
	if err != nil {
		t.Fatal(err)
	}
	if set.AccessToken == "" || set.RefreshToken == "" || set.TokenType != TokenTypeBearer {
		t.Fatalf("invalid token set: %#v", set)
	}
	if _, err := service.ExchangeCode(client.ID, code, client.RedirectURIs[0], verifier); err == nil {
		t.Fatal("authorization code must be one-time")
	}
	grant, err := service.ValidateAccessToken(set.AccessToken)
	if err != nil || grant.UserID != "usr_admin" {
		t.Fatalf("validate access token: %#v %v", grant, err)
	}
	refreshed, err := service.Refresh(client.ID, set.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken == set.AccessToken || refreshed.RefreshToken == set.RefreshToken {
		t.Fatal("refresh must rotate tokens")
	}
	if _, err := service.Refresh(client.ID, set.RefreshToken); err == nil {
		t.Fatal("old refresh token must be invalid after rotation")
	}
}

func TestAuthorizationRejectsBadRedirectAndPKCE(t *testing.T) {
	service, err := New(filepath.Join(t.TempDir(), "oauth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RegisterClient(ClientMetadata{
		RedirectURIs: []string{"http://example.com/callback"},
	}); err == nil {
		t.Fatal("non-loopback http redirect must be rejected")
	}
	client, err := service.RegisterClient(ClientMetadata{
		RedirectURIs: []string{"https://client.example/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ValidateAuthorization(client.ID, client.RedirectURIs[0], "challenge", "plain"); err == nil {
		t.Fatal("plain PKCE must be rejected")
	}
	if _, err := service.ValidateAuthorization(client.ID, "https://client.example/other", "challenge", CodeChallengeMethodS256); err == nil {
		t.Fatal("unregistered redirect must be rejected")
	}
}
