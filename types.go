package mcpcenter

import "time"

const (
	TransportStreamableHTTP = "streamable-http"
	TransportStdio          = "stdio"

	AuthNone    = "none"
	AuthHeaders = "headers"
)

type HealthPolicy struct {
	HealthCheckEnabled       bool  `json:"health_check_enabled"`
	CheckIntervalSeconds     int64 `json:"check_interval_seconds,omitempty"`
	ProbeTimeoutSeconds      int64 `json:"probe_timeout_seconds,omitempty"`
	AutoReconnect            bool  `json:"auto_reconnect"`
	ReconnectIntervalSeconds int64 `json:"reconnect_interval_seconds,omitempty"`
}

type Definition struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	DefaultInclude bool              `json:"default_include_in_environment"`
	Transport      string            `json:"transport"`
	AuthMode       string            `json:"auth_mode"`
	Disabled       bool              `json:"disabled,omitempty"`
	Endpoint       string            `json:"endpoint,omitempty"`
	HeaderRefs     map[string]string `json:"header_refs,omitempty"`
	Executable     string            `json:"executable,omitempty"`
	Args           []string          `json:"args,omitempty"`
	EnvRefs        map[string]string `json:"env_refs,omitempty"`
	HealthPolicy   HealthPolicy      `json:"health_policy"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type Config struct {
	Name           string            `json:"name"`
	DefaultInclude bool              `json:"default_include_in_environment"`
	Transport      string            `json:"transport"`
	AuthMode       string            `json:"auth_mode"`
	Disabled       bool              `json:"disabled,omitempty"`
	Endpoint       string            `json:"endpoint,omitempty"`
	HeaderRefs     map[string]string `json:"header_refs,omitempty"`
	Executable     string            `json:"executable,omitempty"`
	Args           []string          `json:"args,omitempty"`
	EnvRefs        map[string]string `json:"env_refs,omitempty"`
	HealthPolicy   HealthPolicy      `json:"health_policy"`
}

type Tool struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	InputSchema any    `json:"input_schema,omitempty"`
}

type HealthState string

const (
	HealthConfigured HealthState = "configured"
	HealthHealthy    HealthState = "healthy"
	HealthError      HealthState = "error"
)

type HealthStatus struct {
	MCPID     string      `json:"mcp_id"`
	State     HealthState `json:"state"`
	ErrorKind string      `json:"error_kind,omitempty"`
	Message   string      `json:"message,omitempty"`
	Tools     []Tool      `json:"tools,omitempty"`
	CheckedAt time.Time   `json:"checked_at"`
}
