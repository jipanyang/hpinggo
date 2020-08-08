package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jipanyang/hpinggo/packetstream"
	"github.com/jipanyang/hpinggo/scanner"
)

// Very basic regression testing

// sudo /usr/local/go/bin/go test ./cmd -v
// sudo /usr/local/go/bin/go test ./cmd -v -ipv6
// TODO: add more comprehensive unit test and intergration test for the packages.
// TODO: refactor scanner library, extract out utility functions.
// TODO: pipe out scan result for the consumption of testing and automation

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
	for idx, ip := range ips {
		t.Logf("Scanning %v ...\n", ips[idx])
		s, err := scanner.NewScanner(ctx, ip, opt)
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
	for idx, ip := range ips {
		t.Logf("Scanning %v ...\n", ips[idx])
		s, err := scanner.NewScanner(ctx, ip, opt)
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

// sudo /usr/local/go/bin/go test -v ./cmd/ -run TestStreamIPv4
//  "-target scanme.com  -s 5432 -p ++79 -S -c 2 -d 500"
func TestStreamIPv4(t *testing.T) {
	if opt.IPv6 {
		t.Skip("skipping test in ipv6 mode.")
	}

	ips, _ := getTargetIPs("scanme.nmap.org", opt.IPv6)
	opt.BaseSourcePort = 5432
	opt.DestPort = "++79"
	opt.TcpSyn = true
	opt.Count = 2  // 2 packets
	opt.Data = 500 // data payload size
	ctx, _ := context.WithCancel(context.Background())
	for idx, ip := range ips {
		t.Logf("Streaming to %v ...\n", ips[idx])
		s, err := packetstream.NewPacketStreamMgmr(ctx, ip, opt)
		if err != nil {
			t.Fatalf("unable to create PacketStreamMgmr for %v: %v", ip, err)
			continue
		}
		if err := s.StartStream(); err != nil {
			t.Fatalf("unable to stream %v: %v", ip, err)
		}
		s.Close()
	}
	// TODO: check console/log output
	// 	--- hpinggo statistic ---
	// 2 packets tramitted, 2 packets received
}
func TestMain(m *testing.M) {
	// Setup()

	// os.Exit() does not respect defer statements
	code := m.Run()
	// CleanUp()
	os.Exit(code)
}
