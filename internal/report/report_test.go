package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Diudiuseven/endpoint-discovery-go/internal/checkpoint"
)

func sampleResults() []checkpoint.Result {
	return []checkpoint.Result{
		{Identity: "http://b/", URL: "http://b/", Grade: "available", StatusCode: 200, Source: "wordlist"},
		{Identity: "http://a/", URL: "http://a/", Grade: "soft404", StatusCode: 200, Source: "wordlist"},
		{Identity: "http://c/", URL: "http://c/", Grade: "redirect", StatusCode: 302, Source: "link",
			Chain: []checkpoint.Hop{{URL: "http://c/landing", StatusCode: 200}}},
	}
}

func TestWriteJSONDeterministic(t *testing.T) {
	var b1, b2 bytes.Buffer
	if err := WriteJSON(&b1, sampleResults()); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&b2, sampleResults()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1.Bytes(), b2.Bytes()) {
		t.Error("JSON output must be byte-identical across runs")
	}

	var decoded []checkpoint.Result
	if err := json.Unmarshal(b1.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 3 {
		t.Fatalf("decoded %d results, want 3", len(decoded))
	}
	// Must be sorted by identity.
	for i := 1; i < len(decoded); i++ {
		if decoded[i-1].Identity > decoded[i].Identity {
			t.Errorf("results not sorted: %s before %s", decoded[i-1].Identity, decoded[i].Identity)
		}
	}
}

func TestWriteSummary(t *testing.T) {
	var b bytes.Buffer
	WriteSummary(&b, sampleResults(), 2)
	out := b.String()
	for _, want := range []string{"available", "soft404", "redirect", "pending"} {
		if !bytes.Contains(b.Bytes(), []byte(want)) {
			t.Errorf("summary missing %q", want)
		}
	}
	_ = out
}
