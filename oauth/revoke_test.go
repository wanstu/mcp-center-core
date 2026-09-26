package oauth

import "testing"

func TestRevokeTokenInvalidatesAccessAndRefreshGrant(t *testing.T) {
	service := newOAuthTestService(t)
	client, verifier, tokenSet := issueOAuthTestTokens(t, service)

	if err := service.RevokeToken(client.ID, tokenSet.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ValidateAccessToken(tokenSet.AccessToken); err == nil {
		t.Fatal("access token should be revoked")
	}
	if _, err := service.Refresh(client.ID, tokenSet.RefreshToken); err == nil {
		t.Fatal("refresh token should be revoked with the grant")
	}

	_, _, tokenSet = issueOAuthTestTokensForClient(t, service, client)
	if err := service.RevokeToken(client.ID, tokenSet.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ValidateAccessToken(tokenSet.AccessToken); err == nil {
		t.Fatal("access token should be revoked when refresh token is revoked")
	}

	_ = verifier
}

func TestRevokeTokenIsIdempotentAndClientBound(t *testing.T) {
	service := newOAuthTestService(t)
	client, _, tokenSet := issueOAuthTestTokens(t, service)
	other, err := service.RegisterClient(ClientMetadata{
		ClientName:   "other",
		RedirectURIs: []string{"https://other.example/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := service.RevokeToken(other.ID, tokenSet.AccessToken); err == nil {
		t.Fatal("different client should not revoke token")
	}
	if _, err := service.ValidateAccessToken(tokenSet.AccessToken); err != nil {
		t.Fatalf("token should remain valid after rejected revoke: %v", err)
	}
	if err := service.RevokeToken(client.ID, "unknown-token"); err != nil {
		t.Fatalf("unknown token revoke should be idempotent: %v", err)
	}
}

func newOAuthTestService(t *testing.T) *Service {
	t.Helper()
	service, err := New(t.TempDir() + "/oauth.json")
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func issueOAuthTestTokens(t *testing.T, service *Service) (Client, string, TokenSet) {
	t.Helper()
	client, err := service.RegisterClient(ClientMetadata{
		ClientName:   "client",
		RedirectURIs: []string{"https://client.example/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, verifier, tokens := issueOAuthTestTokensForClient(t, service, client)
	return client, verifier, tokens
}

func issueOAuthTestTokensForClient(t *testing.T, service *Service, client Client) (Client, string, TokenSet) {
	t.Helper()
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	code, err := service.Approve(AuthorizationRequest{
		UserID:              "usr_test",
		ClientID:            client.ID,
		RedirectURI:         client.RedirectURIs[0],
		Resource:            "https://mcp.example/mcp/server",
		Scope:               "mcp:*",
		CodeChallenge:       PKCEChallengeS256(verifier),
		CodeChallengeMethod: CodeChallengeMethodS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := service.ExchangeCode(client.ID, code, client.RedirectURIs[0], "https://mcp.example/mcp/server", verifier)
	if err != nil {
		t.Fatal(err)
	}
	return client, verifier, tokens
}
