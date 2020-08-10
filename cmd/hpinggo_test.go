package main

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/routing"
	"github.com/jipanyang/hpinggo/packetstream"
	"github.com/jipanyang/hpinggo/scanner"
)

func expectStdoutContains(t *testing.T, ctx context.Context, expectedStrs ...string) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	select {
	case <-ctx.Done():
		w.Close()
		t.Logf("ctx.Done received\n")
		out, _ := ioutil.ReadAll(r)
		os.Stdout = rescueStdout

		for _, expectedStr := range expectedStrs {
			if !strings.Contains(string(out), expectedStr) {
				t.Fatalf("found no expected string: %v in console capture:\n %v", expectedStr, string(out))
			}
		}
	}
}

func getRoute(t *testing.T, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP) {
	var err error
	router, err := routing.New()
	if err != nil {
		t.Fatalf("routing error: %v", err)
	}
	if opt.IPv6 {
		iface, gateway, preferredSrc, err = router.Route(dst)
		if err != nil {
			t.Fatalf("route error: %v", err)
		}
	} else {
		iface, gateway, preferredSrc, err = router.Route(dst)
		if err != nil {
			t.Fatalf("route error: %v", err)
		}
	}
	return
}

// Very basic regression testing

// sudo /usr/local/go/bin/go test ./cmd -v
// sudo /usr/local/go/bin/go test ./cmd -v -ipv6

// TODO: Test IPv6, traceroute
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
	opt.Scan = "80"
	// opt.Scan = "all"
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
	opt.RawSocket = true
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

// sudo /usr/local/go/bin/go test -v ./cmd/ -run TestTraceRouteIPv4Icmp
//  "  -target www.google.com -d 128 -icmp -c 15 -traceroute"
func TestTraceRouteIPv4Icmp(t *testing.T) {
	if opt.IPv6 {
		t.Skip("skipping test in ipv6 mode.")
	}

	ips, _ := getTargetIPs("google.com", opt.IPv6)
	opt.BaseSourcePort = 1234
	opt.Icmp = true
	opt.Count = 15 // 15 packets
	opt.Data = 128 // data payload size
	opt.Interval = 1 * time.Second
	opt.TraceRoute = true
	opt.TraceRouteKeepTTL = false
	ctx, cancel := context.WithCancel(context.Background())

	expectedStrs := []string{
		"hop=1 TimeExceeded(TTLExceeded)",
		"] EchoReply  rtt=",
		"15 packets tramitted,",
	}
	go expectStdoutContains(t, ctx, expectedStrs...)

	for idx, ip := range ips {
		t.Logf("traceroute to %v ...\n", ips[idx])
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
	time.Sleep(2 * time.Second)
}

// sudo /usr/local/go/bin/go test -v ./cmd/ -run TestTraceRouteIPv4Udp
//  "  -d 128 -udp -p +1234 -traceroute -c 10 -ttl 4 --keepttl"
func TestTraceRouteIPv4Udp(t *testing.T) {
	if opt.IPv6 {
		t.Skip("skipping test in ipv6 mode.")
	}
	opt.Icmp = false
	ips, _ := getTargetIPs("google.com", opt.IPv6)
	opt.DestPort = "1234"
	opt.Udp = true
	opt.Count = 10 // 10 packets
	opt.Data = 128 // data payload size
	opt.TraceRoute = true
	opt.TTL = 4
	opt.TraceRouteKeepTTL = true
	ctx, cancel := context.WithCancel(context.Background())

	expectedStrs := []string{
		"hop=4 TimeExceeded(TTLExceeded)",
		"10 packets tramitted, 10 packets received",
	}
	go expectStdoutContains(t, ctx, expectedStrs...)

	for idx, ip := range ips {
		t.Logf("traceroute to %v ...\n", ips[idx])
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
	time.Sleep(2 * time.Second)
}

// sudo /usr/local/go/bin/go test -v ./cmd/ -run TestRandDestIPv4Tcp
//  "    -log_dir /tmp/ -s 2000 -p ++20004 -S -c 4 -rand-dest gw"
// Note, using gw as rand-dest which doesn't have any random section since
// an definite result is preferred to check the result.
func TestRandDestIPv4Tcp(t *testing.T) {
	if opt.IPv6 {
		t.Skip("skipping test in ipv6 mode.")
	}
	iface, gw, src := getRoute(t, net.IPv4zero)

	opt.Icmp = false
	opt.DestPort = "++20004"
	opt.RandDest = gw.String() // using the gw as rand-dest for basic testing
	opt.BaseSourcePort = 2000
	opt.Udp = false
	opt.Count = 4  // 4 packets
	opt.Data = 128 // data payload size
	opt.TcpSyn = true
	opt.Interface = iface.Name

	ctx, cancel := context.WithCancel(context.Background())

	expectedStrs := []string{
		"4 packets tramitted, 4 packets received",
	}
	go expectStdoutContains(t, ctx, expectedStrs...)

	t.Logf("Stream from %v to rand-dest: %v ...\n", src, gw)
	s, err := packetstream.NewPacketStreamMgmr(ctx, net.IPv4zero, opt)
	if err != nil {
		t.Fatalf("unable to create PacketStreamMgmr for %v: %v", gw, err)
	}
	if err := s.StartStream(); err != nil {
		t.Fatalf("unable to stream %v: %v", gw, err)
	}
	s.Close()

	cancel()
	time.Sleep(2 * time.Second)
}

func TestMain(m *testing.M) {
	// Setup()

	// os.Exit() does not respect defer statements
	code := m.Run()
	// CleanUp()
	os.Exit(code)
}
