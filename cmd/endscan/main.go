// Command endscan runs the endpoint discovery engine against a target.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Diudiuseven/endpoint-discovery-go/internal/discovery"
)

type headerFlags map[string]string

func (h headerFlags) String() string { return fmt.Sprint(map[string]string(h)) }
func (h headerFlags) Set(s string) error {
	k, v, ok := strings.Cut(s, ":")
	if !ok || strings.TrimSpace(k) == "" {
		return fmt.Errorf("header must be Name:Value, got %q", s)
	}
	h[strings.TrimSpace(k)] = strings.TrimSpace(v)
	return nil
}

type listFlags []string

func (l *listFlags) String() string { return strings.Join(*l, ",") }
func (l *listFlags) Set(s string) error {
	*l = append(*l, s)
	return nil
}

func main() {
	var (
		target      = flag.String("target", "", "base URL to scan (required)")
		wordsFile   = flag.String("words", "", "file with one candidate path per line")
		concurrency = flag.Int("concurrency", 4, "per-target concurrent requests")
		rps         = flag.Float64("rps", 20, "global requests-per-second cap")
		stateFile   = flag.String("state", "", "checkpoint file for resume")
		expand      = flag.Bool("expand", false, "extract links from available responses")
		maxDepth    = flag.Int("max-depth", 1, "content expansion depth")
		timeout     = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		maxRetries  = flag.Int("max-retries", 3, "retries on 429/5xx/connection errors")
	)
	var headers = headerFlags{}
	var prefixes, excludes listFlags
	flag.Var(headers, "H", "request header 'Name:Value' (repeatable)")
	flag.Var(&prefixes, "prefix", "allowed path prefix (repeatable)")
	flag.Var(&excludes, "exclude", "excluded path prefix (repeatable)")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: -target is required")
		flag.Usage()
		os.Exit(2)
	}
	var words []string
	if *wordsFile != "" {
		b, err := os.ReadFile(*wordsFile)
		if err != nil {
			log.Fatalf("read words: %v", err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if w := strings.TrimSpace(line); w != "" && !strings.HasPrefix(w, "#") {
				words = append(words, w)
			}
		}
	}
	if len(words) == 0 {
		log.Fatal("no candidate paths: provide -words")
	}

	cfg := discovery.Config{
		Target:              *target,
		Wordlist:            words,
		Concurrency:         *concurrency,
		RequestsPerSecond:   *rps,
		StateFile:           *stateFile,
		ExpandFromContent:   *expand,
		MaxExpansionDepth:   *maxDepth,
		Timeout:             *timeout,
		MaxRetries:          *maxRetries,
		Headers:             headers,
		AllowedPathPrefixes: prefixes,
		ExcludePathPrefixes: excludes,
		Logger:              log.New(os.Stderr, "endscan: ", 0),
	}
	eng, err := discovery.NewEngine(cfg)
	if err != nil {
		log.Fatalf("init: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := eng.Run(ctx)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fmt.Println(string(out))
}
