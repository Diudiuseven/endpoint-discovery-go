// Package config defines the engine configuration.
package config

import (
	"encoding/json"
	"os"
	"time"
)

// AuthConfig mirrors httpx.Auth for JSON configuration.
type AuthConfig struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

// ScopeConfig mirrors scope.Rule for JSON configuration.
type ScopeConfig struct {
	AllowedHosts   []string `json:"allowed_hosts"`
	AllowedPorts   []int    `json:"allowed_ports"`
	AllowedSchemes []string `json:"allowed_schemes"`
	PathPrefixes   []string `json:"path_prefixes"`
}

// ExcludeConfig lists exclusion rules.
type ExcludeConfig struct {
	Hosts        []string `json:"hosts"`
	PathPrefixes []string `json:"path_prefixes"`
}

// Config is the full engine configuration.
type Config struct {
	// Targets are the starting URLs (at least one required).
	Targets []string `json:"targets"`
	// Wordlist is the path to a candidate wordlist file (one path per line).
	Wordlist string `json:"wordlist"`

	Scope    ScopeConfig   `json:"scope"`
	Excludes ExcludeConfig `json:"excludes"`

	// RateLimit is the global request rate in requests/second (0 = unlimited).
	RateLimit float64 `json:"rate_limit"`
	// PerTargetConcurrency caps in-flight requests per host.
	PerTargetConcurrency int `json:"per_target_concurrency"`
	// MaxRetries caps retry attempts for rate-limited/failed requests.
	MaxRetries int `json:"max_retries"`
	// RetryBackoffMS is the base backoff in milliseconds.
	RetryBackoffMS int `json:"retry_backoff_ms"`
	// RequestTimeoutMS bounds a single request attempt.
	RequestTimeoutMS int `json:"request_timeout_ms"`
	// MaxRedirects caps followed redirect hops.
	MaxRedirects int `json:"max_redirects"`

	// Checkpoint is the resume-state file path.
	Checkpoint string `json:"checkpoint"`
	// Output is the result JSON file path.
	Output string `json:"output"`

	// Headers attached to every request.
	Headers map[string]string `json:"headers"`
	// Auth attached to every request.
	Auth AuthConfig `json:"auth"`
}

// Defaults returns a configuration with sane defaults filled in.
func Defaults() Config {
	return Config{
		RateLimit:            20,
		PerTargetConcurrency: 4,
		MaxRetries:           3,
		RetryBackoffMS:       200,
		RequestTimeoutMS:     15000,
		MaxRedirects:         10,
		Checkpoint:           "checkpoint.json",
		Output:               "results.json",
	}
}

// Load reads a JSON configuration file.
func Load(path string) (Config, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	cfg.ApplyDefaults()
	return cfg, nil
}

// ApplyDefaults fills zero fields with defaults.
func (c *Config) ApplyDefaults() {
	d := Defaults()
	if c.RateLimit == 0 {
		c.RateLimit = d.RateLimit
	}
	if c.PerTargetConcurrency == 0 {
		c.PerTargetConcurrency = d.PerTargetConcurrency
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = d.MaxRetries
	}
	if c.RetryBackoffMS == 0 {
		c.RetryBackoffMS = d.RetryBackoffMS
	}
	if c.RequestTimeoutMS == 0 {
		c.RequestTimeoutMS = d.RequestTimeoutMS
	}
	if c.MaxRedirects == 0 {
		c.MaxRedirects = d.MaxRedirects
	}
	if c.Checkpoint == "" {
		c.Checkpoint = d.Checkpoint
	}
	if c.Output == "" {
		c.Output = d.Output
	}
}

// RetryBackoff returns the base backoff as a duration.
func (c *Config) RetryBackoff() time.Duration {
	return time.Duration(c.RetryBackoffMS) * time.Millisecond
}

// RequestTimeout returns the per-request timeout as a duration.
func (c *Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutMS) * time.Millisecond
}
