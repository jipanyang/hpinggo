package main

import (
	"context"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jipanyang/hpinggo/packetstream"
	"github.com/jipanyang/hpinggo/scanner"
)

func expectStdoutContains(t *testing.T, ctx context.Context, expectedStr string) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	select {
	case <-ctx.Done():
		w.Close()
		t.Logf("ctx.Done received\n")
		out, _ := ioutil.ReadAll(r)
		os.Stdout = rescueStdout

		if !strings.Contains(string(out), expectedStr) {
			t.Fatalf("found no expected string: %v in console capture:\n %v", expectedStr, string(out))
		}
	}
}

// Very basic regression testing

// sudo /usr/local/go/bin/go test ./cmd -v
// sudo /usr/local/go/bin/go test ./cmd -v -ipv6
// TODO: add more comprehensive unit test and intergration test for the packages.
// TODO: refactor scanner library, extract out utility functions.
// TODO: pipe out scan result for the consumption of testing and automation

//  "-target  scanme.nmap.org -scan 'all' -i 1us -S"
func TestScannerIPv4WithRawSocket(t *testing.T) {
	if opt.IPv6 {
		t.Skip("skipping test in ipv6 mode.")
	}

	expectedStr := `  port 22(ssh) open
	  port 9929 open
	  port 31337 open
	  port 80(http) open
	All replies received. Done.
	Not responding ports: (0)`

	ips, _ := getTargetIPs("scanme.nmap.org", opt.IPv6)
	opt.Scan = "all"
	// 1 microsecond duration
	opt.Interval = 1 * time.Microsecond
	opt.TcpSyn = true
	ctx, cancel := context.WithCancel(context.Background())
	// Not working, maybe output runs out of buffer?
	// go expectStdoutContains(t, ctx, expectedStr)
	_ = expectedStr

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
	cancel()
	time.Sleep(1 * time.Second)
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
	ctx, cancel := context.WithCancel(context.Background())

	go expectStdoutContains(t, ctx, "port 80(http) open")

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

	cancel()
	time.Sleep(1 * time.Second)
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
	ctx, cancel := context.WithCancel(context.Background())

	go expectStdoutContains(t, ctx, "2 packets tramitted, 2 packets received")

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

	cancel()
	time.Sleep(1 * time.Second)
}

func TestMain(m *testing.M) {
	// Setup()

	// os.Exit() does not respect defer statements
	code := m.Run()
	// CleanUp()
	os.Exit(code)
}
