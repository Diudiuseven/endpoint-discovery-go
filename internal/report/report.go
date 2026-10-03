// Package report produces stable, deterministic scan output.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/Diudiuseven/endpoint-discovery-go/internal/checkpoint"
)

// WriteJSON writes results as deterministic JSON (sorted by identity).
func WriteJSON(w io.Writer, results []checkpoint.Result) error {
	sorted := make([]checkpoint.Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Identity < sorted[j].Identity })
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(sorted)
}

// WriteSummary writes a human-readable summary.
func WriteSummary(w io.Writer, results []checkpoint.Result, pending int) {
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Grade]++
	}
	grades := make([]string, 0, len(counts))
	for g := range counts {
		grades = append(grades, g)
	}
	sort.Strings(grades)
	fmt.Fprintf(w, "discovered %d confirmed result(s):\n", len(results))
	for _, g := range grades {
		fmt.Fprintf(w, "  %-22s %d\n", g, counts[g])
	}
	if pending > 0 {
		fmt.Fprintf(w, "  %-22s %d\n", "pending", pending)
	}
	fmt.Fprintln(w, "---")
	for _, r := range results {
		fmt.Fprintf(w, "[%s] %s (status %d, source %s)\n", r.Grade, r.URL, r.StatusCode, r.Source)
	}
}
