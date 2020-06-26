/*
Copyright 2020 Jipan Yang
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// The hpinggo program implements the hping like packet generator and analyzer.
//
// usage:
// hpinggo -- \
// ....       \
// ....

package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"time"

	"flag"

	log "github.com/golang/glog"
	"github.com/jipanyang/hpinggo/config"
)

var (
	mu  sync.Mutex
	cfg = config.Config{Display: func(b []byte) {
		defer mu.Unlock()
		mu.Lock()
		os.Stdout.Write(append(b, '\n'))
	}}

	verboseFlag = flag.Bool("verbose", false, `When set, hpinggo runs in noisy mode`)
)

func init() {
	// Config command-line flags.
	flag.DurationVar(&cfg.PollingInterval, "polling_interval", 30*time.Second, "Interval at which to poll in seconds if polling is specified for query_type.")
	flag.UintVar(&cfg.Count, "count", 0, "Number of polling/streaming events (0 is infinite).")
	flag.StringVar(&cfg.Delimiter, "delimiter", "/", "Delimiter between path nodes in query. Must be a single UTF-8 code point.")
	flag.DurationVar(&cfg.StreamingDuration, "streaming_duration", 0, "Length of time to collect streaming queries (0 is infinite).")
	flag.StringVar(&cfg.DisplayPrefix, "display_prefix", "", "Per output line prefix.")
	flag.StringVar(&cfg.DisplayIndent, "display_indent", "  ", "Output line, per nesting-level indent.")
	flag.StringVar(&cfg.Timestamp, "timestamp", "", "Specify timestamp formatting in output.  One of (<empty string>, on, raw, <FORMAT>) where <empty string> is disabled, on is human readable, raw is int64 nanos since epoch, and <FORMAT> is according to golang time.Format(<FORMAT>)")

	// Shortcut flags that can be used in place of the longform flags above.
	flag.BoolVar(verboseFlag, "vf", *verboseFlag, "Short for verbose.")
	flag.UintVar(&cfg.Count, "c", cfg.Count, "Short for count.")
	flag.StringVar(&cfg.Delimiter, "d", cfg.Delimiter, "Short for delimiter.")
	flag.StringVar(&cfg.Timestamp, "ts", cfg.Timestamp, "Short for timestamp.")
	flag.DurationVar(&cfg.StreamingDuration, "sd", cfg.StreamingDuration, "Short for streaming_duration.")
	flag.DurationVar(&cfg.PollingInterval, "pi", cfg.PollingInterval, "Short for polling_interval.")
}

func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	// Terminate on Ctrl+C.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		cancel()
	}()

	if *verboseFlag {
		log.Infof("Verbose mode enabled. Time %v\n", time.Now())
	}
	displayOptions(ctx)

}

func displayOptions(ctx context.Context) error {
	cfg.Display([]byte("test only"))
	return nil
}
