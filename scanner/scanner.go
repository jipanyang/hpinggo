package scanner

import (
	"errors"
	"fmt"
	log "github.com/golang/glog"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	// "golang.org/x/sys/unix"
	"github.com/jipanyang/hpinggo/options"
)

const (
	MaxPort      = 65535 // Maximum port number
	MaxScanRetry = 2     // Maximum scan retry before getting response
)

// net raw socket implementation, alternative to unix.IPPROTO_RAW
var useListenPacket = bool(false)

type portinfo struct {
	active   int       // writen by receiver, read by sender
	retry    int       // For writer consumtion only.
	sendTime time.Time // Writen by sender, read by receiver.
	recvTime time.Time // for receiver consumtion only
}

// scanner handles scanning a single IP address.
type scanner struct {
	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	dst, gw, src net.IP

	handle   *pcap.Handle
	socketFd int // fd of raw socket
	ipConn   net.PacketConn

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	packetOpts gopacket.SerializeOptions
	buf        gopacket.SerializeBuffer

	// options specified at user command line
	cmdOpts options.Options
	// tracking scan data for each port, using array to avoid lock and simplify update
	portScan         [MaxPort + 1]portinfo
	averageLatencyNs int64 //average RTT for packets sent, in nanosecond
}

// NewScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func NewScanner(ip net.IP, handle *pcap.Handle, fd int, router routing.Router, opt options.Options) (*scanner, error) {
	s := &scanner{
		dst:      ip,
		socketFd: fd,
		packetOpts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf:              gopacket.NewSerializeBuffer(),
		cmdOpts:          opt,
		averageLatencyNs: 0,
	}
	// Figure out the route to the IP.
	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}
	log.Infof("scanning ip %v with interface %v, gateway %v, src %v\n cmdOpts %+v", ip, iface.Name, gw, src, s.cmdOpts)
	s.gw, s.src, s.iface = gw, src, iface

	// Note we could very easily add some BPF filtering here to greatly
	// decrease the number of packets we have to look at when getting back
	// scan results.
	s.handle = handle

	if useListenPacket {
		ipConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
		if err != nil {
			panic(err)
		}
		s.ipConn = ipConn
	}
	// TODO: support port number range
	for port := 0; port <= MaxPort; port++ {
		s.portScan[port] = portinfo{
			active: 1,
			retry:  MaxScanRetry,
		}
	}
	return s, nil
}

func (s *scanner) Close() {
	// handle not owned by scanner
	// s.handle.Close()
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
func (s *scanner) getHwAddr() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := s.dst
	if s.gw != nil {
		arpDst = s.gw
	}
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	// Send a single ARP request packet (we never retry a send, since this
	// is just an example ;)
	if err := s.send(&eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("getHwAddr: timeout getting ARP reply")
		}
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

// scanner scans the dst IP address.
func (s *scanner) Scan() error {
	// if using pcap for sending packets
	var hwaddr net.HardwareAddr
	var err error
	var eth layers.Ethernet
	if s.socketFd <= 0 {
		// First off, get the MAC address we should be sending packets to.
		hwaddr, err = s.getHwAddr()
		if err != nil {
			return err
		}
		// Construct all the network layers we need.
		eth = layers.Ethernet{
			SrcMAC:       s.iface.HardwareAddr,
			DstMAC:       hwaddr,
			EthernetType: layers.EthernetTypeIPv4,
		}
	}
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: 54321,
		DstPort: 0,    // will be incremented during the scan
		SYN:     true, // TODO: populate TCP flags from cmdOpts
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	// Create the flow we expect returning packets to have, so we can check
	// against it and discard useless packets.
	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go s.receiver(ipFlow, stop)
	defer close(stop)
	log.Infof("Start Scan, time: %v", time.Now())
	s.sender(&eth, &ip4, &tcp)

	log.Infof("Return from Scan, socketFd: %v, useListenPacket: %v, time: %v", s.socketFd, useListenPacket, time.Now())
	return nil
}

func (s *scanner) sender(eth *layers.Ethernet, ip4 *layers.IPv4, tcp *layers.TCP) {
	retry := 0
	recvd := 0
	interval := s.cmdOpts.Interval
	for {
		retry++
		active := 0 // Number of active scanning port.

		// Send one packet per loop iteration until we've sent packets
		// to all of ports
		for port, _ := range s.portScan {
			if s.portScan[port].active > 0 && s.portScan[port].retry > 0 {
				active++
				s.portScan[port].retry--
				tcp.DstPort = layers.TCPPort(port)
				s.portScan[port].sendTime = time.Now()
				if useListenPacket {
					_ = eth
					if err := s.rawNetSockSend(tcp); err != nil {
						log.Errorf("error net.ListenPacket socket sending to port %v: %v", tcp.DstPort, err)
					}
				} else if s.socketFd > 0 {
					_ = eth
					if err := s.rawSockSend(ip4, tcp); err != nil {
						log.Errorf("error raw socket sending to port %v: %v", tcp.DstPort, err)
					}
				} else if err := s.send(eth, ip4, tcp); err != nil {
					log.Errorf("error sending to port %v: %v", tcp.DstPort, err)
				}
				time.Sleep(interval)
			}
		}

		latency := time.Duration(s.averageLatencyNs) * time.Nanosecond
		log.V(1).Infof("Average RTT %v", latency)
		if retry > 4 {
			if s.averageLatencyNs != 0 {
				time.Sleep(100 * latency)
			} else {
				time.Sleep(1 * time.Second)
			}
		}
		for port, _ := range s.portScan {
			if s.portScan[port].active == 0 && s.portScan[port].retry > 0 {
				recvd++
			}
		}
		// No more active scanning
		if active == 0 {
			// Have not received any response
			if recvd == 0 {
				time.Sleep(1 * time.Second)
			}
			fmt.Fprintf(os.Stderr, "All replies received. Done.\n")

			fmt.Fprintf(os.Stderr, "Not responding ports: ")
			for port, _ := range s.portScan {
				// Exhausted all reties, but no response
				if s.portScan[port].active > 0 && s.portScan[port].retry == 0 {
					// TODO: get known port name , port_to_name(port)
					fmt.Fprintf(os.Stderr, "(%d) ", port)
				}
			}
			fmt.Fprintf(os.Stderr, "\n")
			break
		}

		// Are we sending too fast
		if recvd == 0 || MaxScanRetry <= retry+2 {
			interval *= 10
			log.Infof("SLOWING DONW to interval %v", interval)
		}
	}
}

// pcap send sends the given layers as a single packet on the network.
func (s *scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.packetOpts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

// Raw socket send
func (s *scanner) rawSockSend(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.packetOpts, l...); err != nil {
		return err
	}
	packetData := s.buf.Bytes()

	ip := []byte(s.dst)
	var dstIp [4]byte
	copy(dstIp[:], ip[:4])

	addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: dstIp,
	}
	err := syscall.Sendto(s.socketFd, packetData, 0, &addr)
	if err != nil {
		log.Fatal("Sendto:", err)
	}
	return nil

}

// Raw socket send
func (s *scanner) rawNetSockSend(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.packetOpts, l...); err != nil {
		return err
	}

	dstIPaddr := net.IPAddr{
		IP: s.dst,
	}

	packetData := s.buf.Bytes()

	_, err := s.ipConn.WriteTo(packetData, &dstIPaddr)
	if err != nil {
		return err
	}
	return nil
}

// receiver watches a handle for incoming responses we might care about, and prints them.
//
// receiver loops until 'stop' is closed.
func (s *scanner) receiver(netFlow gopacket.Flow, stop chan struct{}) {
	// Add basic src and dst bpf filter, should be applicable to both IPv4 and IPv6
	src, dst := netFlow.Endpoints()
	bpffilter := fmt.Sprintf("src %v and dst %v", src, dst)
	fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
	log.V(2).Infof("  Using BPF filter %q\n", bpffilter)

	if err := s.handle.SetBPFFilter(bpffilter); err != nil {
		log.Exitf("SetBPFFilter: %v\n", err)
	}
	packetSrc := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	in := packetSrc.Packets()

	var recvCount int64 = 0
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			net := packet.NetworkLayer()
			if net == nil || net.NetworkFlow() != netFlow {
				panic("packet has no network layer")
			}
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				log.V(6).Infof("packet has not tcp layer")
				continue
			}
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				panic("tcp layer is not tcp layer :-/")
			}
			if tcp.DstPort != 54321 {
				log.V(6).Infof("dst port %v does not match", tcp.DstPort)
			} else if tcp.RST {
				log.V(6).Infof("  port %v closed", tcp.SrcPort)
			} else if tcp.SYN && tcp.ACK {

				if s.portScan[tcp.SrcPort].active == 0 {
					log.Infof("  port %v open, duplicate response ", tcp.SrcPort)
					continue
				}
				recvCount++
				fmt.Fprintf(os.Stderr, "  port %v open\n", tcp.SrcPort)
				s.portScan[tcp.SrcPort].active = 0
				s.portScan[tcp.SrcPort].recvTime = time.Now()
				//TODO: use float variable
				latency := int64((s.portScan[tcp.SrcPort].recvTime.Sub(s.portScan[tcp.SrcPort].sendTime)) / time.Nanosecond)
				s.averageLatencyNs = (s.averageLatencyNs*(recvCount-1) + latency) / recvCount

			} else {
				log.V(7).Infof("ignoring useless packet")
			}

		}
	}
}
