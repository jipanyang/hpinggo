package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jipanyang/hpinggo/scanner"
)

// Very basic regression testing

// sudo /usr/local/go/bin/go test ./cmd -v
// sudo /usr/local/go/bin/go test ./cmd -v -ipv6
// TODO: add more comprehensive unit test and intergration test for the packages.
// TODO: refactor scanner library, extract out utility functions.
// TODO: pipe out scan result for consumption of testing and automation

//  "-target  scanme.nmap.org -scan 'all' -i 1us -S"
func TestScannerIPv4(t *testing.T) {
	if opt.IPv6 {
		t.Skip("skipping test in ipv6 mode.")
	}

	ips, _ := getTargetIPs("scanme.nmap.org", opt.IPv6)
	opt.Scan = "all"
	// 1 microsecond duration
	// opt.Interval = time.ParseDuration("1us")
	opt.Interval = 1 * time.Microsecond
	opt.TcpSyn = true
	ctx, _ := context.WithCancel(context.Background())
	fd := open_sockraw()
	for idx, ip := range ips {
		t.Logf("Scanning %v ...\n", ips[idx])
		s, err := scanner.NewScanner(ctx, ip, fd, opt)
		if err != nil {
			t.Fatalf("unable to create scanner for %v: %v", ip, err)
			continue
		}
		if err := s.Scan(); err != nil {
			t.Fatalf("unable to scan %v: %v", ip, err)
		}
		s.Close()
	}
}

// -target scanme.nmap.org  -scan '80,443'   -i 10ms -S  -raw_socket=false
func TestScannerIPv4WithPcapSender(t *testing.T) {
	if opt.IPv6 {
		t.Skip("skipping test in ipv6 mode.")
	}

	ips, _ := getTargetIPs("scanme.nmap.org", opt.IPv6)
	opt.Scan = "80,443"
	opt.Interval = 10 * time.Microsecond
	opt.TcpSyn = true
	opt.RawSocket = false
	ctx, _ := context.WithCancel(context.Background())
	fd := open_sockraw()
	for idx, ip := range ips {
		t.Logf("Scanning %v ...\n", ips[idx])
		s, err := scanner.NewScanner(ctx, ip, fd, opt)
		if err != nil {
			t.Fatalf("unable to create scanner for %v: %v", ip, err)
			continue
		}
		if err := s.Scan(); err != nil {
			t.Fatalf("unable to scan %v: %v", ip, err)
		}
		s.Close()
	}
}

func TestMain(m *testing.M) {
	// Setup()

	// os.Exit() does not respect defer statements
	code := m.Run()
	// CleanUp()
	os.Exit(code)
}
