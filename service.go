package mcpcenter

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Service struct {
	store  *FileStore
	now    func() time.Time
	lookup func(string) (string, bool)

	auditMu   sync.RWMutex
	auditSink AuditSink

	runtimeMu sync.Mutex
	runtime   map[string]*runtimeEntry
}

func New(store *FileStore) *Service {
	return &Service{
		store: store, now: time.Now, lookup: os.LookupEnv,
		runtime: map[string]*runtimeEntry{},
	}
}

func (s *Service) Store() *FileStore { return s.store }

func (s *Service) List() ([]Definition, error) {
	items, err := s.store.List()
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	return items, nil
}

func (s *Service) Get(id string) (Definition, error) { return s.store.Get(id) }

func (s *Service) Add(cfg Config) (Definition, error) {
	def, err := Validate(cfg)
	if err != nil {
		return Definition{}, err
	}
	items, err := s.List()
	if err != nil {
		return Definition{}, err
	}
	for _, item := range items {
		if strings.EqualFold(item.Name, def.Name) {
			return Definition{}, fmt.Errorf("mcp %q already exists", def.Name)
		}
	}
	id, err := newID("mcp")
	if err != nil {
		return Definition{}, err
	}
	now := s.now().UTC()
	def.ID, def.CreatedAt, def.UpdatedAt = id, now, now
	if err := s.store.Put(def); err != nil {
		return Definition{}, err
	}
	return cloneDefinition(def), nil
}

func (s *Service) Update(id string, cfg Config) (Definition, error) {
	current, err := s.store.Get(strings.TrimSpace(id))
	if err != nil {
		return Definition{}, err
	}
	def, err := Validate(cfg)
	if err != nil {
		return Definition{}, err
	}
	items, err := s.List()
	if err != nil {
		return Definition{}, err
	}
	for _, item := range items {
		if item.ID != id && strings.EqualFold(item.Name, def.Name) {
			return Definition{}, fmt.Errorf("mcp %q already exists", def.Name)
		}
	}
	def.ID = current.ID
	def.CreatedAt = current.CreatedAt
	def.UpdatedAt = s.now().UTC()
	if err := s.store.Put(def); err != nil {
		return Definition{}, err
	}
	s.invalidateRuntime(def.ID)
	return cloneDefinition(def), nil
}

func (s *Service) Remove(id string) error {
	id = strings.TrimSpace(id)
	if err := s.store.Delete(id); err != nil {
		return err
	}
	s.invalidateRuntime(id)
	return nil
}

func Validate(cfg Config) (Definition, error) {
	def := Definition{
		Name:           strings.TrimSpace(cfg.Name),
		DefaultInclude: cfg.DefaultInclude,
		Transport:      strings.TrimSpace(cfg.Transport),
		AuthMode:       strings.TrimSpace(cfg.AuthMode),
		Endpoint:       strings.TrimSpace(cfg.Endpoint),
		HeaderRefs:     trimMap(cfg.HeaderRefs),
		Executable:     strings.TrimSpace(cfg.Executable),
		Args:           append([]string(nil), cfg.Args...),
		EnvRefs:        trimMap(cfg.EnvRefs),
		HealthPolicy:   cfg.HealthPolicy,
	}
	if def.Name == "" {
		return Definition{}, fmt.Errorf("mcp name is required")
	}
	if def.Transport == "" {
		def.Transport = TransportStreamableHTTP
	}
	if def.AuthMode == "" {
		def.AuthMode = AuthNone
	}
	if def.HealthPolicy.ProbeTimeoutSeconds < 0 || def.HealthPolicy.CheckIntervalSeconds < 0 || def.HealthPolicy.ReconnectIntervalSeconds < 0 {
		return Definition{}, fmt.Errorf("mcp health policy intervals must be nonnegative")
	}
	if def.HealthPolicy.HealthCheckEnabled && (def.HealthPolicy.CheckIntervalSeconds <= 0 || def.HealthPolicy.ProbeTimeoutSeconds <= 0) {
		return Definition{}, fmt.Errorf("health check requires positive check and probe intervals")
	}
	if def.HealthPolicy.AutoReconnect && def.HealthPolicy.ReconnectIntervalSeconds <= 0 {
		return Definition{}, fmt.Errorf("auto reconnect requires a positive reconnect interval")
	}
	switch def.Transport {
	case TransportStreamableHTTP:
		if def.Executable != "" || len(def.Args) > 0 || len(def.EnvRefs) > 0 {
			return Definition{}, fmt.Errorf("streamable-http mcp cannot configure stdio fields")
		}
		if !validHTTPTemplate(def.Endpoint) {
			return Definition{}, fmt.Errorf("mcp endpoint must be a valid http(s) URL or environment template")
		}
		switch def.AuthMode {
		case AuthNone:
			if len(def.HeaderRefs) > 0 {
				return Definition{}, fmt.Errorf("auth mode none cannot configure header_refs")
			}
		case AuthHeaders:
			if len(def.HeaderRefs) == 0 {
				return Definition{}, fmt.Errorf("auth mode headers requires header_refs")
			}
			for k, v := range def.HeaderRefs {
				if !containsEnvRef(v) {
					return Definition{}, fmt.Errorf("mcp header %q must use an environment reference", k)
				}
			}
		default:
			return Definition{}, fmt.Errorf("unsupported mcp auth_mode %q", def.AuthMode)
		}
	case TransportStdio:
		if def.AuthMode != AuthNone {
			return Definition{}, fmt.Errorf("stdio mcp auth_mode must be none")
		}
		if def.Endpoint != "" || len(def.HeaderRefs) > 0 {
			return Definition{}, fmt.Errorf("stdio mcp cannot configure endpoint or header_refs")
		}
		if def.Executable == "" {
			return Definition{}, fmt.Errorf("stdio mcp executable is required")
		}
		for k, v := range def.EnvRefs {
			if !containsEnvRef(v) {
				return Definition{}, fmt.Errorf("stdio env_refs[%q] must use an environment reference", k)
			}
		}
	default:
		return Definition{}, fmt.Errorf("unsupported mcp transport %q", def.Transport)
	}
	return def, nil
}

func (s *Service) expand(value string) (string, bool) {
	unresolved := false
	out := os.Expand(value, func(key string) string {
		name, fallback, hasFallback := key, "", false
		if i := strings.Index(key, ":-"); i >= 0 {
			name, fallback, hasFallback = key[:i], key[i+2:], true
		}
		if current, ok := s.lookup(name); ok && (!hasFallback || current != "") {
			return current
		}
		if hasFallback {
			return fallback
		}
		unresolved = true
		return ""
	})
	return out, unresolved
}

func (s *Service) resolveMap(refs map[string]string) (map[string]string, bool) {
	if len(refs) == 0 {
		return nil, false
	}
	out := make(map[string]string, len(refs))
	unresolved := false
	for k, v := range refs {
		value, missing := s.expand(v)
		out[k] = value
		unresolved = unresolved || missing
	}
	return out, unresolved
}

func validHTTPTemplate(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	expanded := os.Expand(value, func(string) string { return "mcp-center-ref" })
	parsed, err := url.Parse(expanded)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func containsEnvRef(value string) bool {
	found := false
	_ = os.Expand(value, func(string) string {
		found = true
		return ""
	})
	return found
}

func trimMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range in {
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func newID(prefix string) (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}
