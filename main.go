// Command endpoint-discovery runs a web endpoint discovery scan.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Diudiuseven/endpoint-discovery-go/internal/config"
	"github.com/Diudiuseven/endpoint-discovery-go/internal/engine"
	"github.com/Diudiuseven/endpoint-discovery-go/internal/report"
)

func main() {
	var cfg config.Config
	var configPath string
	var target string

	flag.StringVar(&configPath, "config", "", "path to JSON configuration file")
	flag.StringVar(&target, "target", "", "target URL (overrides config targets)")
	flag.StringVar(&cfg.Wordlist, "wordlist", "", "path to candidate wordlist")
	flag.StringVar(&cfg.Checkpoint, "checkpoint", "", "checkpoint file path")
	flag.StringVar(&cfg.Output, "output", "", "result JSON file path")
	flag.Float64Var(&cfg.RateLimit, "rate", 0, "global request rate in requests/second (0 = unlimited)")
	flag.IntVar(&cfg.PerTargetConcurrency, "concurrency", 0, "per-target in-flight request cap")
	flag.IntVar(&cfg.MaxRetries, "retries", 0, "max retry attempts for rate-limited/failed requests")
	flag.Parse()

	if configPath != "" {
		loaded, err := config.Load(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		cfg = loaded
	}
	if target != "" {
		cfg.Targets = append(cfg.Targets, target)
	}
	cfg.ApplyDefaults()

	eng, err := engine.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := eng.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	results := eng.Results()
	if cfg.Output != "" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		if err := report.WriteJSON(f, results); err != nil {
			f.Close()
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		f.Close()
	}
	report.WriteSummary(os.Stdout, results, eng.PendingCount())
}
