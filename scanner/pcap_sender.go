package scanner

import (
	"context"
	"errors"
	"fmt"
	log "github.com/golang/glog"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// pcapSender handles packets to be sent on pcap interface
// One usage example:
// sudo /usr/local/go/bin/go run cmd/hpinggo.go -target www.yahoo.com  -scan '80,443' -i 1ms -S -logtostderr=false -raw_socket=false
type pcapSender struct {
	ctx context.Context

	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	dst, gw, src net.IP

	handle *pcap.Handle

	// mac address of nexthop
	dstMac  net.HardwareAddr
	ethType layers.EthernetType

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	packetOpts gopacket.SerializeOptions
	buf        gopacket.SerializeBuffer
}

// NewPcapSender creates a new Sender based on the input info,
// it will use pcap interface for the sending .
func NewPcapSender(ctxParent context.Context, dst net.IP, gw net.IP, src net.IP, iface *net.Interface,
	handle *pcap.Handle) (*pcapSender, error) {

	p := &pcapSender{
		ctx:    ctxParent,
		dst:    dst,
		gw:     gw,
		src:    src,
		iface:  iface,
		handle: handle,
		packetOpts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}

	// If pcap handle is to be used for sending packets, ether layer info should be populated.
	nextHop := dst
	if gw != nil {
		nextHop = gw
	}
	var err error
	tmpIp := nextHop
	if tmpIp = tmpIp.To4(); tmpIp != nil {
		p.dstMac, err = p.getHwAddrWithArp()
		if err != nil {
			return nil, err
		}
		p.ethType = layers.EthernetTypeIPv4
	} else if nextHop = nextHop.To16(); nextHop != nil {
		// For IPv6 nexthop
		p.dstMac, err = p.getHwAddrWithNs()
		if err != nil {
			return nil, err
		}
		p.ethType = layers.EthernetTypeIPv6
	} else {
		return nil, fmt.Errorf("Invalid nexthop: %v", nextHop)
	}

	return p, nil
}

func (p *pcapSender) close() {

}

// pcap send sends the given layers as a single packet on the network.
func (p *pcapSender) rawSend(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(p.buf, p.packetOpts, l...); err != nil {
		return err
	}
	return p.handle.WritePacketData(p.buf.Bytes())
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
func (p *pcapSender) getHwAddrWithArp() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := p.dst
	if p.gw != nil {
		arpDst = p.gw
	}
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       p.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(p.iface.HardwareAddr),
		SourceProtAddress: []byte(p.src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	// Send a single ARP request packet (we never retry a send, since this
	// is just an example ;)
	if err := p.rawSend(&eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("getHwAddr: timeout getting ARP reply")
		}
		data, _, err := p.handle.ReadPacketData()
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

func (p *pcapSender) getHwAddrWithNs() (net.HardwareAddr, error) {
	start := time.Now()
	nsDst := p.dst
	if p.gw != nil {
		nsDst = p.gw
	}

	dstMac, dstIp, err := SolicitedNodeMulticast(nsDst)
	if err != nil {
		return nil, err
	}

	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       p.iface.HardwareAddr,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := layers.IPv6{
		SrcIP:      ipv6LinkLocalUnicastAddr(p.iface),
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
		Data: p.iface.HardwareAddr,
	}

	ns := layers.ICMPv6NeighborSolicitation{
		TargetAddress: nsDst,
		Options:       layers.ICMPv6Options{sourcLinkAddr},
	}

	// Send a single NS request packet
	if err := p.rawSend(&eth, &ip6, &icmp6, &ns); err != nil {
		return nil, err
	}
	// Wait 3 seconds for a Neighbor Advertisement.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("getHwAddrWithNs: timeout getting Neighbor Advertisement")
		}
		data, _, err := p.handle.ReadPacketData()
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

// pcap send sends the given layers as a single packet on the network.
func (p *pcapSender) send(ls []gopacket.Layer, payload []byte) error {
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       p.iface.HardwareAddr,
		DstMAC:       p.dstMac,
		EthernetType: p.ethType,
	}

	// Assuming just one layer for now.
	// TODO: use cases beyond tcp?
	transportLayer := ls[0]
	tcp := transportLayer.(*layers.TCP)

	if p.ethType == layers.EthernetTypeIPv6 {
		ipv6 := layers.IPv6{
			SrcIP:      p.src,
			DstIP:      p.dst,
			Version:    6,
			HopLimit:   255,
			NextHeader: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(&ipv6)
		if err := gopacket.SerializeLayers(p.buf, p.packetOpts, &eth, &ipv6, tcp, gopacket.Payload(payload)); err != nil {
			return err
		}
	} else {
		ipv4 := layers.IPv4{
			SrcIP:    p.src,
			DstIP:    p.dst,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(&ipv4)
		if err := gopacket.SerializeLayers(p.buf, p.packetOpts, &eth, &ipv4, tcp, gopacket.Payload(payload)); err != nil {
			return err
		}
	}

	return p.handle.WritePacketData(p.buf.Bytes())
}
