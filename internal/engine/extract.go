package engine

import (
	"regexp"
	"strings"
)

// linkPatterns find candidate paths/URLs inside response bodies.
var linkPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)url\(\s*["']?([^"')]+)["']?\s*\)`),
	regexp.MustCompile(`https?://[^\s"'<>\\]+`),
}

// extractLinks returns candidate links found in a response body.
func extractLinks(body []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, re := range linkPatterns {
		for _, m := range re.FindAllSubmatch(body, -1) {
			link := ""
			if len(m) > 1 && m[1] != nil {
				link = string(m[1])
			} else if len(m) > 0 {
				link = string(m[0])
			}
			link = strings.TrimSpace(link)
			link = strings.Trim(link, `"'`)
			if link == "" || strings.HasPrefix(link, "#") ||
				strings.HasPrefix(link, "javascript:") ||
				strings.HasPrefix(link, "mailto:") ||
				strings.HasPrefix(link, "data:") {
				continue
			}
			if !seen[link] {
				seen[link] = true
				out = append(out, link)
			}
		}
	}
	return out
}
