package discovery

import "strings"

// redactedValue replaces sensitive header values in logs and output.
const redactedValue = "***"

// RedactedHeaders returns the configured headers with values of sensitive
// names masked. Sensitive matching is case-insensitive and always includes
// Authorization, Cookie, Set-Cookie, Proxy-Authorization and X-Api-Key even
// if not listed in Config.SensitiveHeaders.
func (c *Config) RedactedHeaders() map[string]string {
	sensitive := map[string]bool{
		"authorization":       true,
		"cookie":              true,
		"set-cookie":          true,
		"proxy-authorization": true,
		"x-api-key":           true,
	}
	for _, h := range c.SensitiveHeaders {
		sensitive[strings.ToLower(strings.TrimSpace(h))] = true
	}
	out := make(map[string]string, len(c.Headers))
	for k, v := range c.Headers {
		if sensitive[strings.ToLower(k)] {
			out[k] = redactedValue
		} else {
			out[k] = v
		}
	}
	return out
}
