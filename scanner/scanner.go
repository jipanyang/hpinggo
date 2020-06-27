package scanner

import (
	"errors"
	log "github.com/golang/glog"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

// TODO: IPv6 and various protocol support.
// Only fixed ICMP for now.

// func pkt() []byte {
// 	ip := &layers.IPv4{
// 		SrcIP:    srcip,
// 		DstIP:    dstip,
// 		Protocol: layers.IPProtocolICMPv4,
// 	}
// 	// Our TCP header
// 	icmp := &layers.ICMPv4{
// 		TypeCode: srcport,
// 		DstPort:  dstport,
// 		Seq:      1105024978,
// 		Id:       true,
// 		Window:   14600,
// 	}

// }
// scanner handles scanning a single IP address.
type scanner struct {
	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	dst, gw, src net.IP

	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

// NewScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func NewScanner(ip net.IP, handle *pcap.Handle, router routing.Router) (*scanner, error) {
	s := &scanner{
		dst: ip,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}
	// Figure out the route to the IP.
	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}
	log.Infof("scanning ip %v with interface %v, gateway %v, src %v", ip, iface.Name, gw, src)
	s.gw, s.src, s.iface = gw, src, iface

	// Note we could very easily add some BPF filtering here to greatly
	// decrease the number of packets we have to look at when getting back
	// scan results.
	s.handle = handle
	return s, nil
}

// close cleans up the handle.
func (s *scanner) Close() {
	s.handle.Close()
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
			return nil, errors.New("timeout getting ARP reply")
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

// scan scans the dst IP address of this scanner.
func (s *scanner) Scan() error {
	// First off, get the MAC address we should be sending packets to.
	hwaddr, err := s.getHwAddr()
	if err != nil {
		return err
	}
	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       hwaddr,
		EthernetType: layers.EthernetTypeIPv4,
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
		DstPort: 0, // will be incremented during the scan
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	// Create the flow we expect returning packets to have, so we can check
	// against it and discard useless packets.
	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go s.readResponse(s.handle, ipFlow, stop)
	defer close(stop)
	log.Infof("Start Scan, time: %v", time.Now())
	for {
		// Send one packet per loop iteration until we've sent packets
		// to all of ports [1, 65535].
		if tcp.DstPort < 65535 {
			tcp.DstPort++
			log.V(5).Infof("src %v, dst %v, tcp.DstPort %v", s.src, s.dst, tcp.DstPort)
			if err := s.send(&eth, &ip4, &tcp); err != nil {
				log.Errorf("error sending to port %v: %v", tcp.DstPort, err)
			}
		} else {
			log.Infof("Scan reached port number %v, time: %v", tcp.DstPort, time.Now())
			break
		}
	}
	// We don't know exactly how long it'll take for packets to be
	// sent back to us, but 5 seconds should be more than enough
	// time ;)
	time.Sleep(5 * time.Second)
	log.Infof("Return from Scan, time: %v", time.Now())
	return nil
}

// send sends the given layers as a single packet on the network.
func (s *scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

// readResponse watches a handle for incoming responses we might care about, and prints them.
//
// readResponse loops until 'stop' is closed.
func (s *scanner) readResponse(handle *pcap.Handle, netFlow gopacket.Flow, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			net := packet.NetworkLayer()
			if net == nil {
				log.V(6).Infof("packet has no network layer")
				continue
			}
			if net.NetworkFlow() != netFlow {
				log.V(6).Infof("packet does not match our ip src/dst")
				continue
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
				log.Infof("  port %v open", tcp.SrcPort)
			} else {
				log.V(7).Infof("ignoring useless packet")
			}

		}
	}
}
