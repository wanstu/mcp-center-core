package mcpcenter

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	ImportFormatAuto       = "auto"
	ImportFormatCore       = "mcp-center"
	ImportFormatMCPServers = "mcpServers"

	ConflictError        = "error"
	ConflictSkip         = "skip"
	ConflictUpdateByName = "update_by_name"
)

type ImportResult struct {
	Added   int          `json:"added"`
	Updated int          `json:"updated"`
	Skipped int          `json:"skipped"`
	Items   []Definition `json:"items"`
}

type exportBundle struct {
	Version int      `json:"version"`
	MCPs    []Config `json:"mcps"`
}

type genericBundle struct {
	MCPServers map[string]genericServer `json:"mcpServers"`
}

type genericServer struct {
	URL     string            `json:"url,omitempty"`
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

func (s *Service) ImportJSON(data []byte, format, conflict string) (ImportResult, error) {
	format = strings.TrimSpace(format)
	if format == "" {
		format = ImportFormatAuto
	}
	conflict = strings.TrimSpace(conflict)
	if conflict == "" {
		conflict = ConflictError
	}
	if conflict != ConflictError && conflict != ConflictSkip && conflict != ConflictUpdateByName {
		return ImportResult{}, fmt.Errorf("unsupported import conflict policy %q", conflict)
	}

	configs, err := decodeImport(data, format)
	if err != nil {
		return ImportResult{}, err
	}
	if len(configs) == 0 {
		return ImportResult{}, errors.New("import contains no MCP definitions")
	}

	validated := make([]Definition, 0, len(configs))
	seenNames := map[string]struct{}{}
	for i, cfg := range configs {
		def, err := Validate(cfg)
		if err != nil {
			return ImportResult{}, fmt.Errorf("validate imported MCP %d (%q): %w", i+1, cfg.Name, err)
		}
		key := strings.ToLower(def.Name)
		if _, exists := seenNames[key]; exists {
			return ImportResult{}, fmt.Errorf("import contains duplicate MCP name %q", def.Name)
		}
		seenNames[key] = struct{}{}
		validated = append(validated, def)
	}

	current, err := s.store.List()
	if err != nil {
		return ImportResult{}, err
	}
	byName := make(map[string]int, len(current))
	for i := range current {
		byName[strings.ToLower(current[i].Name)] = i
	}

	now := s.now().UTC()
	result := ImportResult{Items: make([]Definition, 0, len(validated))}
	for _, incoming := range validated {
		key := strings.ToLower(incoming.Name)
		if index, exists := byName[key]; exists {
			switch conflict {
			case ConflictError:
				return ImportResult{}, fmt.Errorf("mcp %q already exists", incoming.Name)
			case ConflictSkip:
				result.Skipped++
				result.Items = append(result.Items, cloneDefinition(current[index]))
				continue
			case ConflictUpdateByName:
				existing := current[index]
				incoming.ID = existing.ID
				incoming.CreatedAt = existing.CreatedAt
				incoming.UpdatedAt = now
				current[index] = incoming
				result.Updated++
				result.Items = append(result.Items, cloneDefinition(incoming))
				continue
			}
		}

		id, err := newID("mcp")
		if err != nil {
			return ImportResult{}, err
		}
		incoming.ID = id
		incoming.CreatedAt = now
		incoming.UpdatedAt = now
		current = append(current, incoming)
		byName[key] = len(current) - 1
		result.Added++
		result.Items = append(result.Items, cloneDefinition(incoming))
	}

	if err := s.store.ReplaceAll(current); err != nil {
		return ImportResult{}, err
	}
	s.DisconnectAll()
	return result, nil
}

func (s *Service) ExportJSON(format string) ([]byte, error) {
	format = strings.TrimSpace(format)
	if format == "" {
		format = ImportFormatCore
	}
	items, err := s.List()
	if err != nil {
		return nil, err
	}

	switch format {
	case ImportFormatCore:
		configs := make([]Config, 0, len(items))
		for _, item := range items {
			configs = append(configs, configFromDefinition(item))
		}
		return json.MarshalIndent(exportBundle{Version: 1, MCPs: configs}, "", "  ")
	case ImportFormatMCPServers:
		servers := make(map[string]genericServer, len(items))
		for _, item := range items {
			switch item.Transport {
			case TransportStreamableHTTP:
				server := genericServer{URL: item.Endpoint}
				if len(item.HeaderRefs) > 0 {
					server.Headers = cloneMap(item.HeaderRefs)
				}
				servers[item.Name] = server
			case TransportStdio:
				servers[item.Name] = genericServer{
					Command: item.Executable,
					Args:    append([]string(nil), item.Args...),
					Env:     cloneMap(item.EnvRefs),
				}
			default:
				return nil, fmt.Errorf("cannot export MCP %q with transport %q", item.Name, item.Transport)
			}
		}
		return json.MarshalIndent(genericBundle{MCPServers: servers}, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported export format %q", format)
	}
}

func decodeImport(data []byte, format string) ([]Config, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, errors.New("import JSON is empty")
	}
	if format == ImportFormatAuto {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(data, &probe); err != nil {
			return nil, fmt.Errorf("decode import JSON: %w", err)
		}
		switch {
		case probe["mcpServers"] != nil:
			format = ImportFormatMCPServers
		case probe["mcps"] != nil:
			format = ImportFormatCore
		default:
			return nil, errors.New("cannot detect import format: expected mcpServers or mcps")
		}
	}

	switch format {
	case ImportFormatCore:
		var bundle exportBundle
		if err := json.Unmarshal(data, &bundle); err != nil {
			return nil, fmt.Errorf("decode MCP Center import: %w", err)
		}
		return bundle.MCPs, nil
	case ImportFormatMCPServers:
		var bundle genericBundle
		if err := json.Unmarshal(data, &bundle); err != nil {
			return nil, fmt.Errorf("decode mcpServers import: %w", err)
		}
		if bundle.MCPServers == nil {
			return nil, errors.New("mcpServers import is missing mcpServers")
		}
		names := make([]string, 0, len(bundle.MCPServers))
		for name := range bundle.MCPServers {
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })

		configs := make([]Config, 0, len(names))
		for _, name := range names {
			server := bundle.MCPServers[name]
			cfg, err := configFromGeneric(name, server)
			if err != nil {
				return nil, err
			}
			configs = append(configs, cfg)
		}
		return configs, nil
	default:
		return nil, fmt.Errorf("unsupported import format %q", format)
	}
}

func configFromGeneric(name string, server genericServer) (Config, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Config{}, errors.New("mcpServers contains an empty server name")
	}
	hasURL := strings.TrimSpace(server.URL) != ""
	hasCommand := strings.TrimSpace(server.Command) != ""
	if hasURL == hasCommand {
		return Config{}, fmt.Errorf("mcpServers[%q] must configure exactly one of url or command", name)
	}

	if hasURL {
		cfg := Config{
			Name:      name,
			Transport: TransportStreamableHTTP,
			AuthMode:  AuthNone,
			Endpoint:  strings.TrimSpace(server.URL),
		}
		if len(server.Headers) > 0 {
			cfg.AuthMode = AuthHeaders
			cfg.HeaderRefs = cloneMap(server.Headers)
		}
		return cfg, nil
	}

	return Config{
		Name:       name,
		Transport:  TransportStdio,
		AuthMode:   AuthNone,
		Executable: strings.TrimSpace(server.Command),
		Args:       append([]string(nil), server.Args...),
		EnvRefs:    cloneMap(server.Env),
	}, nil
}

func configFromDefinition(item Definition) Config {
	return Config{
		Name:           item.Name,
		DefaultInclude: item.DefaultInclude,
		Transport:      item.Transport,
		AuthMode:       item.AuthMode,
		Disabled:       item.Disabled,
		Endpoint:       item.Endpoint,
		HeaderRefs:     cloneMap(item.HeaderRefs),
		Executable:     item.Executable,
		Args:           append([]string(nil), item.Args...),
		EnvRefs:        cloneMap(item.EnvRefs),
		HealthPolicy:   item.HealthPolicy,
	}
}
