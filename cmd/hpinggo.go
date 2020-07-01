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
// sudo hpinggo -target www.google.com  -I wlp3s0  -i 1us -logtostderr=true \
// ....       \
// ....

package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	log "github.com/golang/glog"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/jipanyang/hpinggo/options"
	"github.com/jipanyang/hpinggo/scanner"
	"golang.org/x/sys/unix"
)

var (
	mu  sync.Mutex
	opt = options.Options{Display: func(b []byte) {
		defer mu.Unlock()
		mu.Lock()
		os.Stdout.Write(append(b, '\n'))
	}}

	target = flag.String("target", "", "Name of remote target for the packets")
)

func init() {
	// Config command-line flags.
	flag.DurationVar(&opt.Interval, "interval", 1*time.Second, "Interval at which to send each packet.")
	flag.UintVar(&opt.Count, "count", 0, "Number of polling/streaming events (0 is infinite).")
	flag.StringVar(&opt.Delimiter, "delimiter", "/", "Delimiter between path nodes in query. Must be a single UTF-8 code point.")
	flag.StringVar(&opt.DisplayPrefix, "display_prefix", "", "Per output line prefix.")
	flag.StringVar(&opt.DisplayIndent, "display_indent", "  ", "Output line, per nesting-level indent.")
	flag.StringVar(&opt.Timestamp, "timestamp", "", "Specify timestamp formatting in output")
	flag.BoolVar(&opt.RandDest, "rand-dest", false, "Enables the random destination mode")
	flag.BoolVar(&opt.Ipv6, "ipv6", false, "When set, hpinggo runs in ipv6 mode")
	flag.StringVar(&opt.Interface, "interface", "", "Interface to be used.")
	flag.StringVar(&opt.Scan, "scan", "", "groups of ports to scan. ex. 1-1000,8888")
	flag.BoolVar(&opt.RawSocket, "raw_socket", true, "Use raw socket for sending packets")

	// Shortcut flags that can be used in place of the longform flags above.
	flag.UintVar(&opt.Count, "c", opt.Count, "Short for count.")
	flag.StringVar(&opt.Delimiter, "d", opt.Delimiter, "Short for delimiter.")
	flag.StringVar(&opt.Interface, "I", opt.Delimiter, "Short for interface.")
	flag.StringVar(&opt.Timestamp, "ts", opt.Timestamp, "Short for timestamp.")
	flag.DurationVar(&opt.Interval, "i", opt.Interval, "Short for interval.")
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

	var ips []net.IP

	// Get remote target addresses
	if !opt.RandDest {
		if *target == "" {
			log.Exitf("Remote target missing\n")
		}

		var err error
		ips, err = net.LookupIP(*target)
		if err != nil {
			log.Exitf("Could not get IPs: %v\n", err)
		}
	}
	for _, ip := range ips {
		log.Infof("%s IN A %s\n", *target, ip.String())
	}

	// Get local addresses
	// TODO: make the library functions in separate libraries
	var addrs []net.Addr
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for idx, iface := range interfaces {
		ifAddrs, err := iface.Addrs()
		if err != nil {
			log.Exitf("Could not get interface address: %v\n", err)
		}

		if opt.Interface == "" {
			// TODO: get local addresses when no interface specified
		} else if opt.Interface == iface.Name {
			addrs = ifAddrs
		}
		for j, addr := range ifAddrs {
			log.V(1).Infof("iface: %d name=%s %v, addr: %d %v\n", idx, iface.Name, iface, j, addr)
		}
	}
	log.Infof("To use addrs: %v\n", addrs)

	fd := -1
	if opt.RawSocket {
		fd = open_sockraw()
		log.Infof("Opened raw socket: %v\n", fd)
	}
	pcapHandle := open_pcap(opt.Interface)
	log.Infof("Opened pcap: %v\n", pcapHandle)

	displayOptions(ctx, opt)

	defer util.Run()()
	router, err := routing.New()
	if err != nil {
		log.Fatal("routing error:", err)
	}
	for idx, ip := range ips {
		if ip = ip.To4(); ip == nil {
			log.Infof("non-ipv4: %v", ips[idx])
			continue
		}
		// Note:  newScanner creates and closes a pcap Handle once for
		// every scan target.  We could do much better, were this not an
		// example ;)
		s, err := scanner.NewScanner(ip, pcapHandle, fd, router, opt)
		if err != nil {
			log.Errorf("unable to create scanner for %v: %v", ip, err)
			continue
		}
		if err := s.Scan(); err != nil {
			log.Errorf("unable to scan %v: %v", ip, err)
		}
		s.Close()
	}

}

func displayOptions(ctx context.Context, opt options.Options) error {
	log.Infof("options: %v", opt)
	return nil
}

// TODO: support AF_INET6 for ipv6 based on opt.Ipv6
func open_sockraw() int {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)

	if err != nil || fd < 0 {
		log.Exitf("error creating a raw socket: %v\n", err)
	}
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	if err != nil {
		unix.Close(fd)
		log.Exitf("error enabling SO_BROADCAST: %v\n", err)
	}

	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		unix.Close(fd)
		log.Exitf("error enabling IP_HDRINCL: %v\n", err)
	}
	return fd
}

func open_pcap(ifName string) *pcap.Handle {
	// Open up a pcap handle for packet reads.
	handle, err := pcap.OpenLive(ifName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Exitf("error creating a pcap handle: %v\n", err)
	}
	return handle
}
