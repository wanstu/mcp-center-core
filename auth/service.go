package auth

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
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	PasswordHash string    `json:"password_hash,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type Session struct {
	TokenHash string    `json:"token_hash"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type State struct {
	Version  int       `json:"version"`
	Users    []User    `json:"users"`
	Sessions []Session `json:"sessions"`
}

type Service struct {
	path       string
	mu         sync.Mutex
	now        func() time.Time
	sessionTTL time.Duration
}

func New(path string) (*Service, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("auth: state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s := &Service{path: path, now: time.Now, sessionTTL: 24 * time.Hour}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	return s, s.saveLocked(st)
}

func (s *Service) NeedsBootstrap() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	return len(st.Users) == 0, err
}

func (s *Service) BootstrapAdmin(username, password string) (User, error) {
	username = strings.TrimSpace(username)
	if err := validateCredentials(username, password); err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return User{}, err
	}
	if len(st.Users) != 0 {
		return User{}, errors.New("auth: bootstrap registration is already closed")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	id, err := newID("usr")
	if err != nil {
		return User{}, err
	}
	now := s.now().UTC()
	user := User{ID: id, Username: username, Role: "admin", PasswordHash: hash, CreatedAt: now}
	st.Users = append(st.Users, user)
	if err := s.saveLocked(st); err != nil {
		return User{}, err
	}
	return publicUser(user), nil
}

func (s *Service) Login(username, password string) (string, User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return "", User{}, err
	}
	var user User
	found := false
	for _, item := range st.Users {
		if strings.EqualFold(item.Username, strings.TrimSpace(username)) {
			user, found = item, true
			break
		}
	}
	if !found || !verifyPassword(user.PasswordHash, password) {
		return "", User{}, errors.New("auth: invalid username or password")
	}
	token, err := randomToken(32)
	if err != nil {
		return "", User{}, err
	}
	now := s.now().UTC()
	st.Sessions = append(cleanSessions(st.Sessions, now), Session{
		TokenHash: tokenHash(token), UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(s.sessionTTL),
	})
	if err := s.saveLocked(st); err != nil {
		return "", User{}, err
	}
	return token, publicUser(user), nil
}

func (s *Service) Authenticate(token string) (User, error) {
	if strings.TrimSpace(token) == "" {
		return User{}, errors.New("auth: session token is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return User{}, err
	}
	now := s.now().UTC()
	hash := tokenHash(token)
	userID := ""
	for _, session := range st.Sessions {
		if session.TokenHash == hash && now.Before(session.ExpiresAt) {
			userID = session.UserID
			break
		}
	}
	if userID == "" {
		return User{}, errors.New("auth: session is invalid or expired")
	}
	for _, user := range st.Users {
		if user.ID == userID {
			return publicUser(user), nil
		}
	}
	return User{}, errors.New("auth: session user no longer exists")
}

func (s *Service) Logout(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return err
	}
	hash := tokenHash(token)
	out := st.Sessions[:0]
	for _, session := range st.Sessions {
		if session.TokenHash != hash {
			out = append(out, session)
		}
	}
	st.Sessions = out
	return s.saveLocked(st)
}

func (s *Service) loadLocked() (State, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{Version: 1, Users: []User{}, Sessions: []Session{}}, nil
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
	if st.Users == nil {
		st.Users = []User{}
	}
	if st.Sessions == nil {
		st.Sessions = []Session{}
	}
	st.Sessions = cleanSessions(st.Sessions, s.now().UTC())
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

func validateCredentials(username, password string) error {
	if len(username) < 3 || len(username) > 64 {
		return errors.New("auth: username must be 3-64 characters")
	}
	return validatePassword(password)
}

func validatePassword(password string) error {
	if len(password) < 10 {
		return errors.New("auth: password must be at least 10 characters")
	}
	return nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const memory = 64 * 1024
	const iterations = 3
	const parallelism = 2
	sum := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, 32)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum)), nil
}

func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[3])
	expected, err2 := base64.RawStdEncoding.DecodeString(parts[4])
	if err1 != nil || err2 != nil {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func publicUser(user User) User {
	user.PasswordHash = ""
	return user
}

func cleanSessions(in []Session, now time.Time) []Session {
	out := make([]Session, 0, len(in))
	for _, session := range in {
		if now.Before(session.ExpiresAt) {
			out = append(out, session)
		}
	}
	return out
}

func randomToken(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw), nil
}
