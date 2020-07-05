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
// sudo hpinggo -target www.google.com  -scan 'all' -i 1us -S
// sudo hpinggo -target www.google.com  -scan 'known,!80' -i 1ms -S
// sudo hpinggo -target www.yahoo.com  -scan '0-70,80,443' -I wlp3s0  -i 1ms -S -logtostderr
// sudo hpinggo -target www.yahoo.com  -scan '0-70,80,443' -ipv6  -i 1ms -S

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	log "github.com/golang/glog"
	"github.com/google/gopacket/examples/util"
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
	flag.StringVar(&opt.DisplayPrefix, "display_prefix", "", "Per output line prefix.")
	flag.StringVar(&opt.DisplayIndent, "display_indent", "  ", "Output line, per nesting-level indent.")
	flag.StringVar(&opt.Timestamp, "timestamp", "", "Specify timestamp formatting in output")
	flag.BoolVar(&opt.RandDest, "rand-dest", false, "Enables the random destination mode")
	flag.BoolVar(&opt.Ipv6, "ipv6", false, "When set, hpinggo runs in ipv6 mode")
	flag.StringVar(&opt.Interface, "interface", "", "Interface to be used.")
	flag.StringVar(&opt.Scan, "scan", "", "Scan mode, groups of ports to scan. ex. 1-1000,8888")
	flag.BoolVar(&opt.RawSocket, "raw_socket", true, "Use raw socket for sending packets")

	flag.BoolVar(&opt.TcpFin, "fin", false, "Set tcp FIN flag")
	flag.BoolVar(&opt.TcpSyn, "syn", false, "Set tcp SYN flag")
	flag.BoolVar(&opt.TcpRst, "rst", false, "Set tcp RST flag")
	flag.BoolVar(&opt.TcpPush, "push", false, "Set tcp PSH flag")
	flag.BoolVar(&opt.TcpAck, "ack", false, "Set tcp ACK flag")
	flag.BoolVar(&opt.TcpUrg, "urg", false, "Set tcp URG flag")
	flag.BoolVar(&opt.TcpEce, "ece", false, "Set tcp ECE flag")
	flag.BoolVar(&opt.TcpCwr, "cwr", false, "Set tcp CWR flag")
	flag.BoolVar(&opt.TcpNs, "ns", false, "Set tcp NS flag")

	// Shortcut flags that can be used in place of the longform flags above.
	flag.UintVar(&opt.Count, "c", opt.Count, "Short for count.")
	flag.StringVar(&opt.Interface, "I", opt.Interface, "Short for interface.")
	flag.StringVar(&opt.Timestamp, "ts", opt.Timestamp, "Short for timestamp.")
	flag.DurationVar(&opt.Interval, "i", opt.Interval, "Short for interval.")
	flag.StringVar(&opt.Scan, "8", opt.Scan, "Short for scan.")

	flag.BoolVar(&opt.TcpFin, "F", opt.TcpFin, "Short for fin")
	flag.BoolVar(&opt.TcpSyn, "S", opt.TcpSyn, "Short for fin")
	flag.BoolVar(&opt.TcpRst, "R", opt.TcpRst, "Short for fin")
	flag.BoolVar(&opt.TcpPush, "P", opt.TcpPush, "Short for fin")
	flag.BoolVar(&opt.TcpAck, "A", opt.TcpAck, "Short for fin")
	flag.BoolVar(&opt.TcpUrg, "U", opt.TcpUrg, "Short for fin")
	flag.BoolVar(&opt.TcpEce, "X", opt.TcpEce, "Short for fin")
	flag.BoolVar(&opt.TcpCwr, "Y", opt.TcpCwr, "Short for fin")
	flag.BoolVar(&opt.TcpNs, "Z", opt.TcpNs, "Short for fin")
}

func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	// Terminate on Ctrl+C.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, os.Kill)
		<-c
		cancel()
	}()

	displayOptions(ctx, opt)

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
		log.Infof("%s : %s\n", *target, ip.String())
	}

	fd := -1
	if opt.RawSocket {
		fd = open_sockraw()
		log.Infof("Opened raw socket: %v\n", fd)
	}

	defer util.Run()()

	if opt.Scan != "" {
		for idx, ip := range ips {

			if !opt.Ipv6 {
				if ip = ip.To4(); ip == nil {
					log.Errorf("non-ipv4: %v\n", ips[idx])
					continue
				}
			} else {
				tmpIp := ip
				if tmpIp = tmpIp.To4(); tmpIp != nil {
					log.Errorf("non-ipv6: %v\n", ips[idx])
					continue
				}
				if ip = ip.To16(); ip == nil {
					log.Errorf("non-ipv6: %v\n", ips[idx])
					continue
				}
			}

			fmt.Fprintf(os.Stderr, "Scanning %v ...\n", ips[idx])
			s, err := scanner.NewScanner(ctx, ip, fd, opt)
			if err != nil {
				log.Errorf("unable to create scanner for %v: %v", ip, err)
				continue
			}
			if err := s.Scan(); err != nil {
				log.Errorf("unable to scan %v: %v", ip, err)
			}
			s.Close()

			select {
			case <-time.After(1 * time.Second):
				continue
			case <-ctx.Done():
				return
			}
		}
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
}

func displayOptions(ctx context.Context, opt options.Options) error {
	log.Infof("options: %v", opt)
	return nil
}

// TODO: support AF_INET6 for ipv6 based on opt.Ipv6
func open_sockraw() int {
	var domain int

	if opt.Ipv6 {
		domain = unix.AF_INET6
	} else {
		domain = unix.AF_INET
	}
	fd, err := unix.Socket(domain, unix.SOCK_RAW, unix.IPPROTO_RAW)

	if err != nil || fd < 0 {
		log.Exitf("error creating a raw socket: %v\n", err)
	}
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	if err != nil {
		unix.Close(fd)
		log.Exitf("error enabling SO_BROADCAST: %v\n", err)
	}

	if opt.Ipv6 {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
	} else {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	}

	if err != nil {
		unix.Close(fd)
		log.Exitf("error enabling IP_HDRINCL: %v\n", err)
	}

	return fd
}
