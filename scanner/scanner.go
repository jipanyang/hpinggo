package scanner

import (
	"context"
	"errors"
	"fmt"
	log "github.com/golang/glog"
	"net"
	"os"
	"strconv"
	"strings"
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
	active   bool      // writen by receiver, read by sender
	retry    int       // For writer consumtion only.
	sendTime time.Time // Writen by sender, read by receiver.
	recvTime time.Time // for receiver consumtion only
}

// scanner handles scanning a single IP address.
type scanner struct {
	ctx context.Context

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
	// tracking scan data for each port
	portScan         []portinfo
	averageLatencyNs int64 //average RTT for packets sent, in nanosecond
}

// NewScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func NewScanner(ctxParent context.Context, ip net.IP, fd int, opt options.Options) (*scanner, error) {
	s := &scanner{
		ctx:      ctxParent,
		dst:      ip,
		socketFd: fd,
		packetOpts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf:     gopacket.NewSerializeBuffer(),
		cmdOpts: opt,
		// Cover all ports possible to avoid lock and simplify update
		portScan:         make([]portinfo, MaxPort+1),
		averageLatencyNs: 0,
	}
	// Figure out the route to the IP.
	// TODO: gopacket router will crash if no default ipv6 route  available, fix it.
	router, err := routing.New()
	if err != nil {
		log.Fatal("routing error:", err)
	}
	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}
	log.Infof("scanning ip %v with interface %v, gateway %v, src %v\n cmdOpts %+v", ip, iface.Name, gw, src, s.cmdOpts)
	s.gw, s.src, s.iface = gw, src, iface

	if useListenPacket {
		var ipConn net.PacketConn
		var err error

		if s.cmdOpts.Ipv6 {
			ipConn, err = net.ListenPacket("ip6:tcp", "::")
		} else {
			ipConn, err = net.ListenPacket("ip4:tcp", "0.0.0.0")
		}

		if err != nil {
			panic(err)
		}
		s.ipConn = ipConn
	}

	for port := 0; port <= MaxPort; port++ {
		s.portScan[port] = portinfo{
			active: false,
			retry:  MaxScanRetry,
		}
	}
	s.parsePorts(opt.Scan)
	for port := 0; port <= MaxPort; port++ {
		if !s.portScan[port].active {
			s.portScan[port].retry = 0
		}
	}

	s.open_pcap()

	return s, nil
}

func (s *scanner) parsePorts(ports string) {
	// , is the deliminator
	portsRanges := strings.Split(ports, ",")
	for _, subPortStr := range portsRanges {
		neg := false
		if len(subPortStr) < 1 {
			log.Exitf("Invalid scan ports range: %v\n", ports)
		}
		if subPortStr[0] == '!' {
			neg = true
			subPortStr = subPortStr[1:]
		}

		if strings.Contains(subPortStr, "-") {
			subRanges := strings.Split(subPortStr, "-")
			if len(subRanges) != 2 {
				log.Exitf("Invalid scan ports range: %v\n", ports)
			}

			low, err := strconv.Atoi(subRanges[0])
			if err != nil {
				log.Exitf("Invalid scan ports range: %v, %v\n", ports, err)
			}
			high, err := strconv.Atoi(subRanges[1])
			if err != nil {
				log.Exitf("Invalid scan ports range: %v, %v\n", ports, err)
			}
			if low > high {
				low, high = high, low
			}
			// Not checking boundary, if not withing 0-65535, just crash
			for ; low <= high; low++ {
				s.portScan[low].active = !neg
			}
		} else if strings.Contains(subPortStr, "all") {
			for port := 0; port <= MaxPort; port++ {
				s.portScan[port].active = !neg
			}
		} else if strings.Contains(subPortStr, "known") {
			for port, _ := range layers.TCPPortNames {
				s.portScan[port].active = !neg
			}
		} else { // a single port
			port, err := strconv.Atoi(subPortStr)
			if err != nil {
				log.Exitf("Invalid scan ports range: %v, %v\n", ports, err)
			}
			s.portScan[port].active = !neg
		}
	}
}

func (s *scanner) open_pcap() {
	var ifName string

	if s.cmdOpts.Interface != "" {
		ifName = s.cmdOpts.Interface
	} else {
		ifName = s.iface.Name
	}

	// Open up a pcap handle for packet reads.
	handle, err := pcap.OpenLive(ifName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Exitf("error creating a pcap handle: %v\n", err)
	}
	log.Infof("Opened pcap handle %+v", handle)
	s.handle = handle
}

func (s *scanner) Close() {
	// remove the filter to get any packet to get out of handle.getNextBufPtrLocked()
	// Otherwise pcap handle will wait for packet which matches the filter.
	if err := s.handle.SetBPFFilter(""); err != nil {
		log.Exitf("SetBPFFilter: %v\n", err)
	}
	s.handle.Close()
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
func (s *scanner) getHwAddr() (net.HardwareAddr, error) {
	if s.cmdOpts.Ipv6 {
		return s.getHwAddrWithNs()
	}
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

// ipv6LinkLocalUnicastAddr returns an IPv6 link-local unicast address
// on the given network interface for tests. It returns net.IPv6zero if no
// suitable address is found.
func ipv6LinkLocalUnicastAddr(ifi *net.Interface) net.IP {
	if ifi == nil {
		return net.IPv6zero
	}
	ifat, err := ifi.Addrs()
	if err != nil {
		return net.IPv6zero
	}
	for _, ifa := range ifat {
		if ifa, ok := ifa.(*net.IPNet); ok {
			if ifa.IP.To4() == nil && ifa.IP.IsLinkLocalUnicast() {
				return ifa.IP
			}
		}
	}
	return net.IPv6zero
}

// Typical Neighbor Solicitation messages are multicast for address resolution
// and unicast when the reach ability of a neighboring node is being verified.
// SolicitedNodeMulticast returns the solicited-node multicast address for
// an IPv6 address.
// For a multicast Neighbor Solicitation message, the Destination Address field is
// set to the Ethernet MAC address that corresponds to the solicited-node address of the target.
// For a unicast Neighbor Solicitation message, the Destination Address field is set to the unicast MAC
// address of the neighbor.
// In the IPv6 header of the Neighbor Solicitation message, you will find these settings:
// The Source Address field is set to either a unicast IPv6 address assigned to the sending interface or,
// during duplicate address detection, the unspecified address (::).
// For a multicast Neighbor Solicitation, the Destination Address field is set to the solicited node
// address of the target. For a unicast Neighbor Solicitation, the Destination Address field is set to
// the unicast address of the target.

func SolicitedNodeMulticast(ip net.IP) (net.HardwareAddr, net.IP, error) {
	if ip.To16() == nil || ip.To4() != nil {
		return nil, nil, fmt.Errorf("not IPv6 address: %q", ip.String())
	}

	// Fixed prefix, and add low 24 bits taken from input address.
	slma := net.HardwareAddr{0x33, 0x33, 0xff, 0x00, 0x00, 0x00}
	for i := 3; i > 0; i-- {
		slma[6-i] = ip[16-i]
	}
	// Fixed prefix, and low 24 bits taken from input address.
	snm := net.ParseIP("ff02::1:ff00:0")
	for i := 13; i < 16; i++ {
		snm[i] = ip[i]
	}

	log.Infof("slma: %v, snm %v", slma, snm)
	return slma, snm, nil
}

func (s *scanner) getHwAddrWithNs() (net.HardwareAddr, error) {
	start := time.Now()
	nsDst := s.dst
	if s.gw != nil {
		nsDst = s.gw
	}

	dstMac, dstIp, err := SolicitedNodeMulticast(nsDst)
	if err != nil {
		return nil, err
	}

	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := layers.IPv6{
		SrcIP:      ipv6LinkLocalUnicastAddr(s.iface),
		DstIP:      dstIp,
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolICMPv6,
	}

	icmp6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
		// Checksum: ,
	}
	icmp6.SetNetworkLayerForChecksum(&ip6)

	sourcLinkAddr := layers.ICMPv6Option{
		Type: layers.ICMPv6OptSourceAddress,
		Data: s.iface.HardwareAddr,
	}

	ns := layers.ICMPv6NeighborSolicitation{
		TargetAddress: nsDst,
		Options:       layers.ICMPv6Options{sourcLinkAddr},
	}

	// Send a single NS request packet
	if err := s.send(&eth, &ip6, &icmp6, &ns); err != nil {
		return nil, err
	}
	// Wait 3 seconds for a Neighbor Advertisement.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("getHwAddrWithNs: timeout getting Neighbor Advertisement")
		}
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if naLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement); naLayer != nil {
			na := naLayer.(*layers.ICMPv6NeighborAdvertisement)
			if net.IP(na.TargetAddress).Equal(net.IP(nsDst)) {
				for _, option := range na.Options {
					if option.Type == layers.ICMPv6OptTargetAddress {
						return net.HardwareAddr(option.Data), nil
					}
				}

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

	// If pcap handle is to be used for sending packets, ether layer info should be populated.
	// TODO: keep one sending channel only, remove the others after evaluation
	if s.socketFd <= 0 {
		// First off, get the MAC address we should be sending packets to.
		hwaddr, err = s.getHwAddr()
		if err != nil {
			return err
		}
		var ethType layers.EthernetType = layers.EthernetTypeIPv4
		if s.cmdOpts.Ipv6 {
			ethType = layers.EthernetTypeIPv6
		}
		// Construct all the network layers we need.
		eth = layers.Ethernet{
			SrcMAC:       s.iface.HardwareAddr,
			DstMAC:       hwaddr,
			EthernetType: ethType,
		}
	}

	tcp := layers.TCP{
		SrcPort: 54321,
		DstPort: 0, // will be incremented during the scan
		FIN:     s.cmdOpts.TcpFin,
		SYN:     s.cmdOpts.TcpSyn,
		RST:     s.cmdOpts.TcpRst,
		PSH:     s.cmdOpts.TcpPush,
		ACK:     s.cmdOpts.TcpAck,
		URG:     s.cmdOpts.TcpUrg,
		ECE:     s.cmdOpts.TcpEce,
		CWR:     s.cmdOpts.TcpCwr,
		NS:      s.cmdOpts.TcpNs,
	}
	// var networkLayer gopacket.NetworkLayer
	var ipv6 layers.IPv6
	var ipv4 layers.IPv4

	if s.cmdOpts.Ipv6 {
		ipv6 = layers.IPv6{
			SrcIP:      s.src,
			DstIP:      s.dst,
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(&ipv6)
	} else {
		ipv4 = layers.IPv4{
			SrcIP:    s.src,
			DstIP:    s.dst,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(&ipv4)
	}

	// Create the flow we expect returning packets to have, so we can check
	// against it and discard useless packets.
	var endpointType gopacket.EndpointType
	endpointType = layers.EndpointIPv4
	if s.cmdOpts.Ipv6 {
		endpointType = layers.EndpointIPv6
	}
	ipFlow := gopacket.NewFlow(endpointType, s.dst, s.src)

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go s.receiver(ipFlow, stop)
	defer close(stop)
	log.Infof("Start Scan, time: %v", time.Now())
	if s.cmdOpts.Ipv6 {
		s.sender(&eth, &ipv6, &tcp)
	} else {
		s.sender(&eth, &ipv4, &tcp)
	}

	log.Infof("Return from Scan, socketFd: %v, useListenPacket: %v, time: %v", s.socketFd, useListenPacket, time.Now())
	return nil
}

func (s *scanner) sender(eth *layers.Ethernet, netLayer gopacket.NetworkLayer, tcp *layers.TCP) {
	retry := 0
	interval := s.cmdOpts.Interval

	for {
		retry++
		activePorts := 0 // Number of active scanning port.
		recvd := 0

		// Send one packet per loop iteration until we've sent packets
		// to all of ports
		for port, _ := range s.portScan {
			if s.portScan[port].active && s.portScan[port].retry > 0 {
				activePorts++
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
					switch v := netLayer.(type) {
					case *layers.IPv4:
						if err := s.rawSockSend(v, tcp); err != nil {
							log.Errorf("error raw socket sending to port %v: %v", tcp.DstPort, err)
						}
					case *layers.IPv6:
						if err := s.rawSockSend(v, tcp); err != nil {
							log.Errorf("error raw socket sending to port %v: %v", tcp.DstPort, err)
						}
					default:
						log.Errorf("cannot use layer type %v for tcp checksum network layer", netLayer.LayerType())
					}

				} else {
					switch v := netLayer.(type) {
					case *layers.IPv4:
						if err := s.send(eth, v, tcp); err != nil {
							log.Errorf("error sending to port %v: %v", tcp.DstPort, err)
						}
					case *layers.IPv6:
						if err := s.send(eth, v, tcp); err != nil {
							log.Errorf("error sending to port %v: %v", tcp.DstPort, err)
						}
					default:
						log.Errorf("cannot use layer type %v for tcp checksum network layer", netLayer.LayerType())
					}
				}
				select {
				case <-time.After(interval):
					continue
				case <-s.ctx.Done():
					fmt.Fprintf(os.Stderr, "Asked to terminiate early \n")
					return
				}

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
			if !s.portScan[port].active && s.portScan[port].retry > 0 {
				recvd++
			}
		}
		// No more active scanning
		if activePorts == 0 {
			// Have not received any response
			if recvd == 0 {
				time.Sleep(1 * time.Second)
			}
			log.Infof("Finish Scan, time: %v", time.Now())
			fmt.Fprintf(os.Stderr, "All replies received. Done.\n")
			fmt.Fprintf(os.Stderr, "Not responding ports: ")
			for port, _ := range s.portScan {
				// Exhausted all reties, but no response
				if s.portScan[port].active && s.portScan[port].retry == 0 {
					// TODO: get known port name , port_to_name(port)
					fmt.Fprintf(os.Stderr, "(%v) ", layers.TCPPort(port))
				}
			}
			fmt.Fprintf(os.Stderr, "\n\n")
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

	if !s.cmdOpts.Ipv6 {

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
	} else {
		var dstIp [16]byte
		copy(dstIp[:], ip[:16])

		addr := syscall.SockaddrInet6{
			Port: 0,
			Addr: dstIp,
		}
		err := syscall.Sendto(s.socketFd, packetData, 0, &addr)
		if err != nil {
			log.Fatal("Sendto:", err)
		}
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
	log.Infof("Using BPF filter %q\n", bpffilter)

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

			log.V(7).Infof("Received packet: %v", packet)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				log.Infof("packet has not tcp layer: %v", packet)
				continue
			}
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				panic("tcp layer is not tcp layer :-/")
			}
			if tcp.DstPort != 54321 {
				log.V(6).Infof("dst port %v does not match", tcp.DstPort)
			} else if tcp.RST {
				log.Infof("  port %v closed", tcp.SrcPort)
			} else if tcp.SYN && tcp.ACK { //
				if !s.portScan[tcp.SrcPort].active {
					log.Infof("  port %v open, duplicate response ", tcp.SrcPort)
					continue
				}
				recvCount++
				fmt.Fprintf(os.Stderr, "  port %v open\n", tcp.SrcPort)
				s.portScan[tcp.SrcPort].active = false
				s.portScan[tcp.SrcPort].recvTime = time.Now()
				//TODO: use float variable
				latency := int64((s.portScan[tcp.SrcPort].recvTime.Sub(s.portScan[tcp.SrcPort].sendTime)) / time.Nanosecond)
				s.averageLatencyNs = (s.averageLatencyNs*(recvCount-1) + latency) / recvCount
			} else {
				log.V(7).Infof("ignoring useless(?) packet")
			}

		}
	}
}
