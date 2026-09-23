package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	CodeChallengeMethodS256 = "S256"
	TokenTypeBearer         = "Bearer"
)

type ClientMetadata struct {
	ClientName    string   `json:"client_name,omitempty"`
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types,omitempty"`
	ResponseTypes []string `json:"response_types,omitempty"`
}

type Client struct {
	ID            string    `json:"client_id"`
	ClientName    string    `json:"client_name,omitempty"`
	RedirectURIs  []string  `json:"redirect_uris"`
	GrantTypes    []string  `json:"grant_types"`
	ResponseTypes []string  `json:"response_types"`
	CreatedAt     time.Time `json:"created_at"`
}

type AuthorizationRequest struct {
	UserID              string
	ClientID            string
	RedirectURI         string
	Resource            string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type authorizationCode struct {
	Hash                string    `json:"hash"`
	UserID              string    `json:"user_id"`
	ClientID            string    `json:"client_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Resource            string    `json:"resource"`
	Scope               string    `json:"scope,omitempty"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
}

type tokenGrant struct {
	AccessHash  string    `json:"access_hash"`
	RefreshHash string    `json:"refresh_hash"`
	UserID      string    `json:"user_id"`
	ClientID    string    `json:"client_id"`
	Resource    string    `json:"resource"`
	Scope       string    `json:"scope,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	RefreshAt   time.Time `json:"refresh_expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type AccessGrant struct {
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Resource  string    `json:"resource"`
	Scope     string    `json:"scope,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TokenSet struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type State struct {
	Version int                 `json:"version"`
	Clients []Client            `json:"clients"`
	Codes   []authorizationCode `json:"codes"`
	Tokens  []tokenGrant        `json:"tokens"`
}

type Service struct {
	path       string
	mu         sync.Mutex
	now        func() time.Time
	codeTTL    time.Duration
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func New(path string) (*Service, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("oauth: state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("oauth: create state directory: %w", err)
	}
	s := &Service{
		path: path, now: time.Now,
		codeTTL: 10 * time.Minute, accessTTL: time.Hour, refreshTTL: 30 * 24 * time.Hour,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	return s, s.saveLocked(st)
}

func (s *Service) RegisterClient(metadata ClientMetadata) (Client, error) {
	normalized, err := normalizeClientMetadata(metadata)
	if err != nil {
		return Client{}, err
	}
	id, err := randomOpaque("client", 18)
	if err != nil {
		return Client{}, err
	}
	client := Client{
		ID: id, ClientName: normalized.ClientName,
		RedirectURIs:  normalized.RedirectURIs,
		GrantTypes:    normalized.GrantTypes,
		ResponseTypes: normalized.ResponseTypes,
		CreatedAt:     s.now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return Client{}, err
	}
	st.Clients = append(st.Clients, client)
	if err := s.saveLocked(st); err != nil {
		return Client{}, err
	}
	return cloneClient(client), nil
}

func (s *Service) GetClient(id string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return Client{}, err
	}
	for _, client := range st.Clients {
		if client.ID == strings.TrimSpace(id) {
			return cloneClient(client), nil
		}
	}
	return Client{}, fmt.Errorf("oauth: client %q not found", id)
}

func (s *Service) ValidateAuthorization(clientID, redirectURI, challenge, method string) (Client, error) {
	client, err := s.GetClient(clientID)
	if err != nil {
		return Client{}, err
	}
	if !slices.Contains(client.ResponseTypes, "code") || !slices.Contains(client.GrantTypes, "authorization_code") {
		return Client{}, errors.New("oauth: client does not support authorization code")
	}
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		return Client{}, errors.New("oauth: redirect_uri does not match registered client")
	}
	if strings.TrimSpace(challenge) == "" {
		return Client{}, errors.New("oauth: code_challenge is required")
	}
	if method != CodeChallengeMethodS256 {
		return Client{}, errors.New("oauth: code_challenge_method must be S256")
	}
	return client, nil
}

func (s *Service) Approve(req AuthorizationRequest) (string, error) {
	if strings.TrimSpace(req.UserID) == "" {
		return "", errors.New("oauth: user_id is required")
	}
	if _, err := s.ValidateAuthorization(req.ClientID, req.RedirectURI, req.CodeChallenge, req.CodeChallengeMethod); err != nil {
		return "", err
	}
	resource, err := normalizeResource(req.Resource)
	if err != nil {
		return "", err
	}
	code, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	item := authorizationCode{
		Hash: tokenHash(code), UserID: req.UserID, ClientID: req.ClientID,
		RedirectURI: req.RedirectURI, Resource: resource, Scope: normalizeScope(req.Scope),
		CodeChallenge: req.CodeChallenge, CodeChallengeMethod: req.CodeChallengeMethod,
		CreatedAt: now, ExpiresAt: now.Add(s.codeTTL),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return "", err
	}
	st.Codes = append(cleanCodes(st.Codes, now), item)
	if err := s.saveLocked(st); err != nil {
		return "", err
	}
	return code, nil
}

func (s *Service) ExchangeCode(clientID, code, redirectURI, resource, verifier string) (TokenSet, error) {
	if len(verifier) < 43 || len(verifier) > 128 {
		return TokenSet{}, errors.New("oauth: code_verifier must be 43-128 characters")
	}
	now := s.now().UTC()
	hash := tokenHash(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return TokenSet{}, err
	}
	index := -1
	var item authorizationCode
	for i, candidate := range st.Codes {
		if candidate.Hash == hash {
			index, item = i, candidate
			break
		}
	}
	if index < 0 || !now.Before(item.ExpiresAt) {
		return TokenSet{}, errors.New("oauth: authorization code is invalid or expired")
	}
	// Consume the code before issuing tokens so it remains one-time even if later validation fails.
	st.Codes = append(st.Codes[:index], st.Codes[index+1:]...)
	normalizedResource, resourceErr := normalizeResource(resource)
	if resourceErr != nil || item.ClientID != clientID || item.RedirectURI != redirectURI || item.Resource != normalizedResource {
		_ = s.saveLocked(st)
		return TokenSet{}, errors.New("oauth: authorization code client, redirect, or resource mismatch")
	}
	if item.CodeChallengeMethod != CodeChallengeMethodS256 || pkceChallenge(verifier) != item.CodeChallenge {
		_ = s.saveLocked(st)
		return TokenSet{}, errors.New("oauth: PKCE verification failed")
	}
	set, grant, err := s.issueTokens(item.UserID, item.ClientID, item.Resource, item.Scope, now)
	if err != nil {
		return TokenSet{}, err
	}
	st.Tokens = append(cleanTokens(st.Tokens, now), grant)
	if err := s.saveLocked(st); err != nil {
		return TokenSet{}, err
	}
	return set, nil
}

func (s *Service) Refresh(clientID, refreshToken string) (TokenSet, error) {
	now := s.now().UTC()
	hash := tokenHash(refreshToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return TokenSet{}, err
	}
	index := -1
	var current tokenGrant
	for i, grant := range st.Tokens {
		if grant.RefreshHash == hash {
			index, current = i, grant
			break
		}
	}
	if index < 0 || !now.Before(current.RefreshAt) || current.ClientID != clientID {
		return TokenSet{}, errors.New("oauth: refresh token is invalid or expired")
	}
	// Rotate refresh tokens. A successful refresh invalidates both old tokens.
	st.Tokens = append(st.Tokens[:index], st.Tokens[index+1:]...)
	set, grant, err := s.issueTokens(current.UserID, current.ClientID, current.Resource, current.Scope, now)
	if err != nil {
		return TokenSet{}, err
	}
	st.Tokens = append(cleanTokens(st.Tokens, now), grant)
	if err := s.saveLocked(st); err != nil {
		return TokenSet{}, err
	}
	return set, nil
}

func (s *Service) ValidateAccessToken(token string) (AccessGrant, error) {
	now := s.now().UTC()
	hash := tokenHash(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return AccessGrant{}, err
	}
	for _, grant := range st.Tokens {
		if grant.AccessHash == hash && now.Before(grant.ExpiresAt) {
			return AccessGrant{
				UserID: grant.UserID, ClientID: grant.ClientID, Resource: grant.Resource,
				Scope: grant.Scope, ExpiresAt: grant.ExpiresAt,
			}, nil
		}
	}
	return AccessGrant{}, errors.New("oauth: access token is invalid or expired")
}

// ValidateAccessTokenForResource prevents a token issued for one MCP resource
// from being replayed against another resource server.
func (s *Service) ValidateAccessTokenForResource(token, resource string) (AccessGrant, error) {
	grant, err := s.ValidateAccessToken(token)
	if err != nil {
		return AccessGrant{}, err
	}
	normalized, err := normalizeResource(resource)
	if err != nil {
		return AccessGrant{}, err
	}
	if grant.Resource != normalized {
		return AccessGrant{}, errors.New("oauth: access token is not valid for this resource")
	}
	return grant, nil
}

func (s *Service) issueTokens(userID, clientID, resource, scope string, now time.Time) (TokenSet, tokenGrant, error) {
	access, err := randomToken(32)
	if err != nil {
		return TokenSet{}, tokenGrant{}, err
	}
	refresh, err := randomToken(40)
	if err != nil {
		return TokenSet{}, tokenGrant{}, err
	}
	grant := tokenGrant{
		AccessHash: tokenHash(access), RefreshHash: tokenHash(refresh),
		UserID: userID, ClientID: clientID, Resource: resource, Scope: scope,
		CreatedAt: now, ExpiresAt: now.Add(s.accessTTL), RefreshAt: now.Add(s.refreshTTL),
	}
	return TokenSet{
		AccessToken: access, TokenType: TokenTypeBearer,
		ExpiresIn: int64(s.accessTTL / time.Second), RefreshToken: refresh, Scope: scope,
	}, grant, nil
}

func normalizeClientMetadata(meta ClientMetadata) (ClientMetadata, error) {
	meta.ClientName = strings.TrimSpace(meta.ClientName)
	if len(meta.RedirectURIs) == 0 {
		return ClientMetadata{}, errors.New("oauth: redirect_uris is required")
	}
	seen := map[string]struct{}{}
	redirects := make([]string, 0, len(meta.RedirectURIs))
	for _, raw := range meta.RedirectURIs {
		raw = strings.TrimSpace(raw)
		if err := validateRedirectURI(raw); err != nil {
			return ClientMetadata{}, err
		}
		if _, exists := seen[raw]; exists {
			continue
		}
		seen[raw] = struct{}{}
		redirects = append(redirects, raw)
	}
	meta.RedirectURIs = redirects
	if len(meta.GrantTypes) == 0 {
		meta.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(meta.ResponseTypes) == 0 {
		meta.ResponseTypes = []string{"code"}
	}
	for _, grant := range meta.GrantTypes {
		if grant != "authorization_code" && grant != "refresh_token" {
			return ClientMetadata{}, fmt.Errorf("oauth: unsupported grant_type %q", grant)
		}
	}
	for _, response := range meta.ResponseTypes {
		if response != "code" {
			return ClientMetadata{}, fmt.Errorf("oauth: unsupported response_type %q", response)
		}
	}
	if slices.Contains(meta.GrantTypes, "authorization_code") && !slices.Contains(meta.ResponseTypes, "code") {
		return ClientMetadata{}, errors.New("oauth: authorization_code requires response_type code")
	}
	return meta, nil
}

func normalizeResource(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("oauth: invalid resource %q", raw)
	}
	if u.Fragment != "" || u.User != nil {
		return "", errors.New("oauth: resource must not contain fragment or userinfo")
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if u.Scheme != "http" || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return "", errors.New("oauth: resource must use https or loopback http")
		}
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}
	u.RawFragment = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("oauth: invalid redirect_uri %q", raw)
	}
	if u.Fragment != "" {
		return errors.New("oauth: redirect_uri must not contain a fragment")
	}
	if u.User != nil {
		return errors.New("oauth: redirect_uri must not contain userinfo")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" {
		return errors.New("oauth: redirect_uri must use https or loopback http")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return errors.New("oauth: insecure redirect_uri is allowed only for loopback clients")
}

func (s *Service) loadLocked() (State, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{Version: 1, Clients: []Client{}, Codes: []authorizationCode{}, Tokens: []tokenGrant{}}, nil
	}
	if err != nil {
		return State{}, err
	}
	var st State
	if len(data) > 0 {
		if err := json.Unmarshal(data, &st); err != nil {
			return State{}, err
		}
	}
	if st.Version == 0 {
		st.Version = 1
	}
	if st.Clients == nil {
		st.Clients = []Client{}
	}
	if st.Codes == nil {
		st.Codes = []authorizationCode{}
	}
	if st.Tokens == nil {
		st.Tokens = []tokenGrant{}
	}
	now := s.now().UTC()
	st.Codes = cleanCodes(st.Codes, now)
	st.Tokens = cleanTokens(st.Tokens, now)
	return st, nil
}

func (s *Service) saveLocked(st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(s.path)
		if err2 := os.Rename(tmp, s.path); err2 != nil {
			return err2
		}
	}
	return nil
}

func cleanCodes(in []authorizationCode, now time.Time) []authorizationCode {
	out := make([]authorizationCode, 0, len(in))
	for _, item := range in {
		if now.Before(item.ExpiresAt) {
			out = append(out, item)
		}
	}
	return out
}

func cleanTokens(in []tokenGrant, now time.Time) []tokenGrant {
	out := make([]tokenGrant, 0, len(in))
	for _, item := range in {
		// Keep expired access grants while their refresh token is still alive.
		if now.Before(item.RefreshAt) {
			out = append(out, item)
		}
	}
	return out
}

func cloneClient(in Client) Client {
	in.RedirectURIs = append([]string(nil), in.RedirectURIs...)
	in.GrantTypes = append([]string(nil), in.GrantTypes...)
	in.ResponseTypes = append([]string(nil), in.ResponseTypes...)
	return in
}

func normalizeScope(scope string) string {
	fields := strings.Fields(scope)
	if len(fields) == 0 {
		return ""
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(fields))
	for _, item := range fields {
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return strings.Join(out, " ")
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomOpaque(prefix string, size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// PKCEChallengeS256 is exported for protocol adapters and tests.
func PKCEChallengeS256(verifier string) string { return pkceChallenge(verifier) }
