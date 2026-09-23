package access

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	ChannelBearer = "bearer"
	ChannelHeader = "header"
	ChannelQuery  = "query"
)

var (
	headerNamePattern = regexp.MustCompile("^[!#$%&'*+.^_\\x60|\\x7e0-9A-Za-z-]+$")
	queryNamePattern  = regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
)

type Settings struct {
	BearerEnabled bool   `json:"bearer_enabled"`
	HeaderEnabled bool   `json:"header_enabled"`
	HeaderName    string `json:"header_name"`
	QueryEnabled  bool   `json:"query_enabled"`
	QueryName     string `json:"query_name"`
}

type Credential struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	SecretPrefix string     `json:"secret_prefix"`
	Enabled      bool       `json:"enabled"`
	AllowBearer  bool       `json:"allow_bearer"`
	AllowHeader  bool       `json:"allow_header"`
	AllowQuery   bool       `json:"allow_query"`
	Scopes       []string   `json:"scopes"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

type CreateInput struct {
	Name        string     `json:"name"`
	Enabled     bool       `json:"enabled"`
	AllowBearer bool       `json:"allow_bearer"`
	AllowHeader bool       `json:"allow_header"`
	AllowQuery  bool       `json:"allow_query"`
	Scopes      []string   `json:"scopes,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type UpdateInput = CreateInput

type CreatedCredential struct {
	Credential Credential `json:"credential"`
	Secret     string     `json:"secret"`
}

type Principal struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	Scopes      []string `json:"scopes"`
	AuthChannel string   `json:"auth_channel"`
}

type record struct {
	Credential Credential `json:"credential"`
	SecretHash string     `json:"secret_hash"`
}

type state struct {
	Version     int      `json:"version"`
	Settings    Settings `json:"settings"`
	Credentials []record `json:"credentials"`
}

type Service struct {
	path string
	mu   sync.Mutex
	now  func() time.Time
}

func New(path string) (*Service, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("access: state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("access: create state directory: %w", err)
	}
	s := &Service{path: path, now: time.Now}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	return s, s.saveLocked(st)
}

func DefaultSettings() Settings {
	return Settings{BearerEnabled: true, HeaderEnabled: true, HeaderName: "X-MCP-Token", QueryEnabled: false, QueryName: "mcp_token"}
}

func (s *Service) Settings() (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return Settings{}, err
	}
	return st.Settings, nil
}

func (s *Service) UpdateSettings(input Settings) (Settings, error) {
	normalized, err := normalizeSettings(input)
	if err != nil {
		return Settings{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return Settings{}, err
	}
	st.Settings = normalized
	if err := s.saveLocked(st); err != nil {
		return Settings{}, err
	}
	return normalized, nil
}

func (s *Service) List() ([]Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(st.Credentials))
	for _, item := range st.Credentials {
		out = append(out, cloneCredential(item.Credential))
	}
	return out, nil
}

func (s *Service) Create(input CreateInput) (CreatedCredential, error) {
	normalized, err := normalizeCredentialInput(input)
	if err != nil {
		return CreatedCredential{}, err
	}
	secret, err := randomSecret()
	if err != nil {
		return CreatedCredential{}, err
	}
	id, err := randomID("cred")
	if err != nil {
		return CreatedCredential{}, err
	}
	now := s.now().UTC()
	credential := Credential{
		ID: id, Name: normalized.Name, SecretPrefix: secretPrefix(secret),
		Enabled: normalized.Enabled, AllowBearer: normalized.AllowBearer, AllowHeader: normalized.AllowHeader, AllowQuery: normalized.AllowQuery,
		Scopes: append([]string(nil), normalized.Scopes...), ExpiresAt: cloneTime(normalized.ExpiresAt), CreatedAt: now, UpdatedAt: now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return CreatedCredential{}, err
	}
	for _, item := range st.Credentials {
		if strings.EqualFold(item.Credential.Name, credential.Name) {
			return CreatedCredential{}, fmt.Errorf("access: credential %q already exists", credential.Name)
		}
	}
	st.Credentials = append(st.Credentials, record{Credential: credential, SecretHash: hashSecret(secret)})
	if err := s.saveLocked(st); err != nil {
		return CreatedCredential{}, err
	}
	return CreatedCredential{Credential: cloneCredential(credential), Secret: secret}, nil
}

func (s *Service) Update(id string, input UpdateInput) (Credential, error) {
	normalized, err := normalizeCredentialInput(input)
	if err != nil {
		return Credential{}, err
	}
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return Credential{}, err
	}
	index := -1
	for i, item := range st.Credentials {
		if item.Credential.ID == id {
			index = i
			continue
		}
		if strings.EqualFold(item.Credential.Name, normalized.Name) {
			return Credential{}, fmt.Errorf("access: credential %q already exists", normalized.Name)
		}
	}
	if index < 0 {
		return Credential{}, fmt.Errorf("access: credential %q not found", id)
	}
	current := st.Credentials[index]
	current.Credential.Name = normalized.Name
	current.Credential.Enabled = normalized.Enabled
	current.Credential.AllowBearer = normalized.AllowBearer
	current.Credential.AllowHeader = normalized.AllowHeader
	current.Credential.AllowQuery = normalized.AllowQuery
	current.Credential.Scopes = append([]string(nil), normalized.Scopes...)
	current.Credential.ExpiresAt = cloneTime(normalized.ExpiresAt)
	current.Credential.UpdatedAt = s.now().UTC()
	st.Credentials[index] = current
	if err := s.saveLocked(st); err != nil {
		return Credential{}, err
	}
	return cloneCredential(current.Credential), nil
}

func (s *Service) Delete(id string) error {
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return err
	}
	for i, item := range st.Credentials {
		if item.Credential.ID == id {
			st.Credentials = append(st.Credentials[:i], st.Credentials[i+1:]...)
			return s.saveLocked(st)
		}
	}
	return fmt.Errorf("access: credential %q not found", id)
}

func (s *Service) Verify(secret, channel string) (Principal, error) {
	secret = strings.TrimSpace(secret)
	channel = strings.TrimSpace(strings.ToLower(channel))
	if secret == "" {
		return Principal{}, errors.New("access: credential secret is required")
	}
	if !slices.Contains([]string{ChannelBearer, ChannelHeader, ChannelQuery}, channel) {
		return Principal{}, fmt.Errorf("access: unsupported channel %q", channel)
	}
	sum := sha256.Sum256([]byte(secret))
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return Principal{}, err
	}
	for i, item := range st.Credentials {
		expected, err := hex.DecodeString(item.SecretHash)
		if err != nil || len(expected) != len(sum) {
			continue
		}
		if subtle.ConstantTimeCompare(sum[:], expected) != 1 {
			continue
		}
		credential := item.Credential
		if !credential.Enabled {
			return Principal{}, errors.New("access: credential is disabled")
		}
		if credential.ExpiresAt != nil && !now.Before(*credential.ExpiresAt) {
			return Principal{}, errors.New("access: credential is expired")
		}
		if !channelAllowed(credential, channel) {
			return Principal{}, fmt.Errorf("access: credential is not allowed through %s", channel)
		}
		credential.LastUsedAt = cloneTime(&now)
		st.Credentials[i].Credential = credential
		if err := s.saveLocked(st); err != nil {
			return Principal{}, err
		}
		return Principal{ID: credential.ID, DisplayName: credential.Name, Scopes: append([]string(nil), credential.Scopes...), AuthChannel: channel}, nil
	}
	return Principal{}, errors.New("access: credential is invalid")
}

func ScopeContains(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == "mcp:*" || scope == strings.TrimSpace(required) {
			return true
		}
	}
	return false
}

func normalizeSettings(input Settings) (Settings, error) {
	input.HeaderName = strings.TrimSpace(input.HeaderName)
	input.QueryName = strings.TrimSpace(input.QueryName)
	if input.HeaderName == "" {
		input.HeaderName = DefaultSettings().HeaderName
	}
	if input.QueryName == "" {
		input.QueryName = DefaultSettings().QueryName
	}
	if !headerNamePattern.MatchString(input.HeaderName) {
		return Settings{}, errors.New("access: invalid header name")
	}
	switch strings.ToLower(input.HeaderName) {
	case "authorization", "cookie", "host", "content-length", "connection", "transfer-encoding", "upgrade", "proxy-authorization", "proxy-authenticate", "te", "trailer":
		return Settings{}, fmt.Errorf("access: header %q is reserved", input.HeaderName)
	}
	if !queryNamePattern.MatchString(input.QueryName) {
		return Settings{}, errors.New("access: invalid query parameter name")
	}
	return input, nil
}

func normalizeCredentialInput(input CreateInput) (CreateInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return CreateInput{}, errors.New("access: credential name is required")
	}
	if len(input.Name) > 80 {
		return CreateInput{}, errors.New("access: credential name must be at most 80 characters")
	}
	if !input.AllowBearer && !input.AllowHeader && !input.AllowQuery {
		return CreateInput{}, errors.New("access: credential must allow at least one channel")
	}
	input.Scopes = normalizeScopes(input.Scopes)
	if len(input.Scopes) == 0 {
		input.Scopes = []string{"mcp:*"}
	}
	if input.ExpiresAt != nil {
		t := input.ExpiresAt.UTC()
		input.ExpiresAt = &t
	}
	return input, nil
}

func normalizeScopes(input []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(input))
	for _, raw := range input {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

func channelAllowed(credential Credential, channel string) bool {
	switch channel {
	case ChannelBearer:
		return credential.AllowBearer
	case ChannelHeader:
		return credential.AllowHeader
	case ChannelQuery:
		return credential.AllowQuery
	default:
		return false
	}
}

func (s *Service) loadLocked() (state, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state{Version: 1, Settings: DefaultSettings(), Credentials: []record{}}, nil
	}
	if err != nil {
		return state{}, err
	}
	var st state
	if len(data) > 0 {
		if err := json.Unmarshal(data, &st); err != nil {
			return state{}, err
		}
	}
	if st.Version == 0 {
		st.Version = 1
	}
	if st.Settings.HeaderName == "" && st.Settings.QueryName == "" {
		st.Settings = DefaultSettings()
	} else {
		normalized, err := normalizeSettings(st.Settings)
		if err != nil {
			return state{}, err
		}
		st.Settings = normalized
	}
	if st.Credentials == nil {
		st.Credentials = []record{}
	}
	return st, nil
}

func (s *Service) saveLocked(st state) error {
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

func randomSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "mcp_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func secretPrefix(secret string) string {
	if len(secret) <= 12 {
		return secret
	}
	return secret[:12]
}

func cloneCredential(in Credential) Credential {
	in.Scopes = append([]string(nil), in.Scopes...)
	in.ExpiresAt = cloneTime(in.ExpiresAt)
	in.LastUsedAt = cloneTime(in.LastUsedAt)
	return in
}

func cloneTime(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	value := in.UTC()
	return &value
}
